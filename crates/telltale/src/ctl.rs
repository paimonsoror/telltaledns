//! `telltale ctl` (REQ: API-008; T7.25): the REST API from a shell. Friendly commands for the
//! common jobs (status, the query log, top lists, block/allow, pause, flush, the running
//! configuration, agent plans) and `get`/`post`/`put`/`delete` for everything else, with an
//! API token (`TELLTALE_TOKEN` or `--token-file`) against a running node. `--json` prints the
//! API's own JSON, for scripts.

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use clap::Subcommand;
use serde_json::{Value, json};

/// Most bytes one answer may have.
const MAX_ANSWER: u64 = 32 << 20;

/// `telltale ctl` commands.
#[derive(Debug, Subcommand)]
pub(crate) enum CtlCommand {
    /// Version, node, uptime, and the last day's numbers.
    Status,
    /// The query log, newest first.
    Queries {
        /// Names containing this.
        #[arg(long)]
        name: Option<String>,
        /// One device (its address).
        #[arg(long)]
        client: Option<String>,
        /// `blocked`, `cached`, `forwarded`, ...
        #[arg(long)]
        status: Option<String>,
        /// Since (RFC 3339 or relative: `-1h`).
        #[arg(long, default_value = "-1h")]
        from: String,
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Top `domains`, `blocked`, `nxdomain`, or `clients`.
    Top {
        kind: String,
        #[arg(long, default_value = "-24h")]
        from: String,
        #[arg(long, default_value_t = 10)]
        limit: u32,
    },
    /// Block a domain (and its subdomains) now: a quick rule.
    Block(RuleArgs),
    /// Allow a domain (and its subdomains) now: a quick rule.
    Allow(RuleArgs),
    /// Remove a quick rule.
    Unrule {
        id: String,
    },
    /// Quick rules.
    Rules,
    /// Pause blocking (everyone, or one group).
    Pause {
        #[arg(long, default_value_t = 10)]
        minutes: u32,
        #[arg(long)]
        group: Option<String>,
    },
    /// Resume blocking.
    Resume {
        #[arg(long)]
        group: Option<String>,
    },
    /// Node maintenance (OPS-010): not ready for new traffic, still answering every query.
    #[command(subcommand)]
    Maintenance(MaintenanceCmd),
    /// Failover drills (CLU-014): a node stops answering chosen devices for a short time; the
    /// report says who switched to another node.
    #[command(subcommand)]
    Drill(DrillCmd),
    /// Staged rollouts (CLU-013): the version baking on the canary nodes, the guard, and the
    /// pin; promote or abort.
    #[command(subcommand)]
    Rollout(RolloutCmd),
    /// The cluster versions the primary keeps, newest first (what to pin back to).
    Versions,
    /// Pin the cluster to a kept version: every node serves its configuration and filter
    /// snapshot (published as a new version) until `unpin`. Changes wait meanwhile.
    Pin {
        /// `<epoch>.<seq>` from `versions`.
        version: String,
        /// Why (shown on the Cluster page, in the alert, and in the audit log).
        #[arg(long)]
        reason: String,
        /// Show what would change without pinning.
        #[arg(long)]
        dry_run: bool,
    },
    /// Unpin the cluster: the primary publishes its current configuration again (through a
    /// staged rollout when canaries are set).
    Unpin {
        /// Show what would change without unpinning.
        #[arg(long)]
        dry_run: bool,
    },
    /// REQ: CLU-001 (ADR-155) — remove a node from the cluster: out of the member list (it stops
    /// voting and being listed) and onto the list of removed nodes, so no node accepts it again.
    /// For a stale record (a node that rejoined under a new ID) or a node being retired. The
    /// primary can't be removed; a node that is up needs `--force`.
    RemoveNode {
        /// The node's ID, as the Cluster page and `telltale cluster status` list it.
        node: String,
        /// Remove it although it is up: its connection is closed and it is refused afterwards.
        #[arg(long)]
        force: bool,
        /// Check and say what would happen, without removing anything.
        #[arg(long)]
        dry_run: bool,
    },
    // REQ: OPS-014
    /// Upgrade the cluster's native nodes to a version, one at a time: replicas
    /// first and the primary last, each back on the version, ready, and in sync before the next.
    /// Kubernetes pods are left to the chart (its `upgradeHook` runs this from the new image
    /// before the pods roll). Each node needs `telltale-update.path` enabled. Needs an admin's
    /// token (agents: `analytics:read` and `cluster:upgrade`).
    Upgrade(UpgradeArgs),
    /// Flush the cache (everything, or one name).
    Flush {
        #[arg(long)]
        name: Option<String>,
        /// Also every name under `--name`.
        #[arg(long)]
        subtree: bool,
    },
    /// REQ: OBS-024 — what a shared configuration (a TOML file, as a Git commit would hold)
    /// would have done to the logged queries, compared with the one in effect. Changes nothing.
    Simulate {
        /// The candidate configuration (shared sections; node-local ones are ignored).
        file: std::path::PathBuf,
        /// How far back: 30m, 24h, 7d (default: `[simulate] default_window`).
        #[arg(long)]
        window: Option<String>,
        /// Where the window ends (RFC 3339 or relative, e.g. -1h; default now).
        #[arg(long)]
        until: Option<String>,
    },
    /// Why a name is or isn't blocked for a device.
    Explain {
        name: String,
        #[arg(long)]
        client: Option<String>,
    },
    /// Filter lists, with download state, unique names, and hits.
    Lists,
    Groups,
    Clients,
    Upstreams,
    /// Device anomalies.
    Anomalies {
        #[arg(long, default_value = "-7d")]
        since: String,
    },
    /// Agent change plans (pending first).
    Plans,
    /// Approve an agent's plan.
    Approve {
        id: String,
    },
    /// Reject an agent's plan.
    Reject {
        id: String,
    },
    /// GET any API path (`/api/v1/` may be left out), with `key=value` query parameters.
    Get {
        path: String,
        params: Vec<String>,
    },
    /// POST JSON (`--data`) to any API path.
    Post {
        path: String,
        #[arg(long)]
        data: Option<String>,
    },
    /// PUT JSON (`--data`) to any API path.
    Put {
        path: String,
        #[arg(long)]
        data: String,
    },
    /// DELETE any API path.
    Delete {
        path: String,
    },
}

/// REQ: OPS-010 — `telltale ctl maintenance`.
#[derive(Debug, Subcommand)]
pub(crate) enum MaintenanceCmd {
    /// Put a node in maintenance: /readyz answers 503 (balancers and Kubernetes stop sending
    /// it new queries), every listener keeps answering, alerts and the health level leave it
    /// out until the window ends. Starting again replaces the window.
    Start {
        /// How long: `90s`, `30m`, `2h`, `1d`, or seconds (default: the node's
        /// `[node] maintenance_default_secs`, an hour).
        #[arg(long = "for", value_parser = parse_duration)]
        for_secs: Option<u32>,
        /// Why (shown on the Cluster page and in the audit log).
        #[arg(long)]
        reason: String,
        /// The node: `local` (the one `--url` points at), or a node's ID, site, or pod name.
        #[arg(long, default_value = "local")]
        node: String,
        /// On the primary under automatic failover: keep the primary role instead of handing it
        /// to another node first.
        #[arg(long)]
        no_handover: bool,
    },
    /// End a node's maintenance now.
    End {
        #[arg(long, default_value = "local")]
        node: String,
    },
    /// Which nodes are in maintenance, until when, and why.
    Status,
}

/// REQ: CLU-014 — `telltale ctl drill`.
#[derive(Debug, Subcommand)]
pub(crate) enum DrillCmd {
    /// Start a failover drill: for 15 s to 5 min the node stops answering the targets
    /// (everyone, `--group`, or `--client`s) while the other nodes serve. Devices without a
    /// working second DNS server lose DNS meanwhile: start with one device.
    Start {
        /// How long: `15s` to `5m`, or seconds (default 60).
        #[arg(long = "for", value_parser = parse_duration)]
        for_secs: Option<u32>,
        /// Drill one group's devices.
        #[arg(long, conflicts_with = "client")]
        group: Option<String>,
        /// Drill these devices (addresses, names, or workloads); repeat for several. With
        /// neither `--group` nor `--client`: everyone.
        #[arg(long)]
        client: Vec<String>,
        /// Why (shown with the report and in the audit log).
        #[arg(long)]
        reason: String,
        /// The node: `local` (the one `--url` points at), or a node's ID, site, or pod name.
        #[arg(long, default_value = "local")]
        node: String,
        /// Check the preconditions and list the devices without dropping anything.
        #[arg(long)]
        dry_run: bool,
        /// Answer REFUSED at once instead of nothing (faster; some devices don't try their
        /// next server on REFUSED).
        #[arg(long)]
        refused: bool,
    },
    /// End a node's drill now (the report still comes).
    Stop {
        #[arg(long, default_value = "local")]
        node: String,
    },
    /// The newest drills, or one drill's report.
    Report { id: Option<String> },
}

/// REQ: OPS-014 — `telltale ctl upgrade`.
#[derive(Debug, clap::Args)]
#[allow(clippy::struct_excessive_bools)] // independent command-line flags
pub(crate) struct UpgradeArgs {
    /// The version: a release (`0.8.0`) or an edge build (`0.8.0-edge.393`, which can be
    /// installed only while it is the newest on the edge channel).
    #[arg(long, required_unless_present = "to_self", conflicts_with = "to_self")]
    pub(crate) to: Option<String>,
    /// This binary's own version (the chart's upgrade hook runs the new image with it).
    #[arg(long)]
    pub(crate) to_self: bool,
    /// Only this node (ID, site, or pod name); repeat for several. Default: every native node
    /// that isn't on the version.
    #[arg(long = "node")]
    pub(crate) nodes: Vec<String>,
    /// How long each node may take to install the version and come back in sync: `90s`,
    /// `10m`, or seconds.
    #[arg(long, value_parser = parse_duration, default_value = UPGRADE_TIMEOUT)]
    pub(crate) timeout: u32,
    /// Leave nodes that are down out instead of stopping. A node that is up but can't take the
    /// request (its update service is off, an update is running there, it follows another
    /// channel, it refuses the version for a day after a rollback) still stops the run: that is
    /// set up wrong, not down.
    #[arg(long)]
    pub(crate) skip_down: bool,
    /// When a node reports the version can't be fetched any more (an edge build main has since
    /// passed): leave that node on its version, say so loudly, and go on, instead of stopping.
    /// The replicas-first order is then not kept for that node in this run.
    #[arg(long)]
    pub(crate) skip_unavailable: bool,
    /// Succeed when nothing answers at `--url` (a first install: no cluster to upgrade yet).
    #[arg(long)]
    pub(crate) skip_if_unreachable: bool,
    /// Say which nodes would be upgraded, in which order, without asking any.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Why, for the audit log (sent with each request as `X-Telltale-Reason`, which an agent
    /// token must send). Default: `telltale ctl upgrade --to <version>`.
    #[arg(long)]
    pub(crate) reason: Option<String>,
}

/// REQ: CLU-013 — `telltale ctl rollout`.
#[derive(Debug, Subcommand)]
pub(crate) enum RolloutCmd {
    /// The version baking, the canaries and what each runs, the time left, the guard's
    /// readings, and the pin.
    Status,
    /// Give the version baking to every node now.
    Promote,
    /// Stop the version baking: pin the cluster to the stable version before it.
    Abort,
}

/// A value safe in one path segment (node names are IDs, sites, or pod names).
fn path_segment(v: &str) -> String {
    let mut out = String::new();
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `90s`, `30m`, `2h`, `1d`, or plain seconds.
pub(crate) fn parse_duration(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let (num, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => s.split_at(i),
        None => (s, "s"),
    };
    let n: u32 = num
        .parse()
        .map_err(|_| format!("`{s}`: a number with s, m, h, or d (e.g. 2h)"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(format!("`{s}`: the unit is s, m, h, or d (e.g. 30m)")),
    };
    n.checked_mul(mult)
        .ok_or_else(|| format!("`{s}` is too long"))
}

/// What a quick rule applies to.
#[derive(Debug, clap::Args)]
pub(crate) struct RuleArgs {
    pub(crate) domain: String,
    /// Stop after this many minutes (default: until removed).
    #[arg(long = "for")]
    pub(crate) minutes: Option<u32>,
    /// Only these groups (repeatable).
    #[arg(long = "group")]
    pub(crate) groups: Vec<String>,
    /// Only these devices: names of configured devices, IPs, or CIDRs (repeatable).
    #[arg(long = "device")]
    pub(crate) devices: Vec<String>,
    /// Why (shown with every decision it makes).
    #[arg(long)]
    pub(crate) note: Option<String>,
    /// Show what would change without changing it.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// A connection to one node's API.
struct Api {
    client: telltale_filter::fetch::Client,
    base: String,
    token: String,
    /// REQ: AGT-003, OPS-014 — why, sent as `X-Telltale-Reason` with every change: the audit log
    /// keeps it, and an agent token's change without one is refused (400).
    reason: Option<String>,
}

impl Api {
    /// The same connection, saying `reason` with every change.
    fn with_reason(&self, reason: String) -> Self {
        Self {
            client: self.client.clone(),
            base: self.base.clone(),
            token: self.token.clone(),
            reason: Some(reason),
        }
    }

    fn url(&self, path: &str) -> String {
        let p = path.trim_start_matches('/');
        let p = p.strip_prefix("api/v1/").unwrap_or(p);
        format!("{}/api/v1/{p}", self.base.trim_end_matches('/'))
    }

    async fn call(
        &self,
        method: http::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, String> {
        match self.call_raw(method, path, body).await? {
            Ok(v) => Ok(v),
            Err((status, v)) => {
                // problem+json: say what's wrong and how to fix it.
                let title = v
                    .get("detail")
                    .or_else(|| v.get("title"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let hint = v
                    .get("hint")
                    .and_then(Value::as_str)
                    .map_or_else(String::new, |h| format!(" ({h})"));
                Err(format!("HTTP {status}: {title}{hint}"))
            }
        }
    }

    /// The answer, or its status and problem body: the outer error is "couldn't ask".
    async fn call_raw(
        &self,
        method: http::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Result<Value, (http::StatusCode, Value)>, String> {
        let url = self.url(path);
        let changes = method != http::Method::GET;
        let mut req = http::Request::builder()
            .method(method)
            .uri(url.as_str())
            .header("authorization", format!("Bearer {}", self.token))
            .header("accept", "application/json");
        if let Some(r) = self.reason.as_deref().filter(|_| changes) {
            req = req.header(telltale_api::auth::routes::REASON, r);
        }
        let bytes = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                serde_json::to_vec(b).map_err(|e| e.to_string())?
            }
            None => Vec::new(),
        };
        let req = req.body(bytes).map_err(|e| e.to_string())?;
        let resp = self
            .client
            .request(req, MAX_ANSWER)
            .await
            .map_err(|e| format!("can't reach {url}: {}", e.message))?;
        let status = resp.status();
        let body = resp.into_body();
        let v: Value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()))
        };
        Ok(if status.is_success() {
            Ok(v)
        } else {
            Err((status, v))
        })
    }

    async fn get(&self, path: &str) -> Result<Value, String> {
        self.call(http::Method::GET, path, None).await
    }
}

/// A query string from `(key, value)` pairs (values percent-encoded).
fn query(pairs: &[(&str, Option<String>)]) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    char::from(b).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    let parts: Vec<String> = pairs
        .iter()
        .filter_map(|(k, v)| v.as_ref().map(|v| format!("{k}={}", enc(v))))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

/// A table: columns padded to their widest cell.
fn table(head: &[&str], rows: &[Vec<String>]) -> String {
    let mut w: Vec<usize> = head.iter().map(|h| h.len()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if let Some(x) = w.get_mut(i) {
                *x = (*x).max(c.chars().count());
            }
        }
    }
    let mut out = String::new();
    let line = |cells: Vec<String>, out: &mut String| {
        let s: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<width$}", width = w.get(i).copied().unwrap_or(0)))
            .collect();
        let _ = writeln!(out, "{}", s.join("  ").trim_end());
    };
    line(head.iter().map(|h| (*h).to_owned()).collect(), &mut out);
    for r in rows {
        line(r.clone(), &mut out);
    }
    out
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => String::new(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_owned))
            .collect::<Vec<_>>()
            .join(", "),
        Some(x) => x.to_string(),
    }
}

fn items(v: &Value) -> &[Value] {
    v.get("items")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// A quick rule's ID from its domain (`block ads.example.com` → `ads-example-com`).
fn rule_id(action: &str, domain: &str) -> String {
    let d: String = domain
        .trim_end_matches('.')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("{action}-{d}")
}

/// The HTTP client for a node's API, also trusting the certificates in `ca` (a node's
/// self-signed `[api] tls`, ADR-149).
pub(crate) fn client(ca: Option<&Path>) -> Result<telltale_filter::fetch::Client, String> {
    let resolver = Arc::new(telltale_filter::fetch::SystemResolver);
    match ca {
        Some(p) => telltale_filter::fetch::Client::with_ca_file(resolver, &p.to_string_lossy()),
        None => telltale_filter::fetch::Client::new(resolver, &[]),
    }
}

/// Runs `cmd` against `base` with `token`; returns the text to print. `ca`: see [`client`].
#[allow(clippy::too_many_lines)] // one arm per command
pub(crate) async fn run(
    base: &str,
    ca: Option<&Path>,
    token: &str,
    cmd: CtlCommand,
    json_out: bool,
) -> Result<String, String> {
    let api = Api {
        client: client(ca)?,
        base: base.to_owned(),
        token: token.to_owned(),
        reason: None,
    };
    let pretty = |v: &Value| serde_json::to_string_pretty(v).unwrap_or_default();
    // Raw calls print JSON whatever --json says.
    let (v, render): Rendered = match cmd {
        CtlCommand::Get { path, params } => {
            let pairs: Vec<(String, String)> = params
                .iter()
                .filter_map(|p| p.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
                .collect();
            let q: Vec<(&str, Option<String>)> = pairs
                .iter()
                .map(|(k, v)| (k.as_str(), Some(v.clone())))
                .collect();
            (api.get(&format!("{path}{}", query(&q))).await?, None)
        }
        CtlCommand::Post { path, data } => {
            let body = data
                .map(|d| serde_json::from_str(&d).map_err(|e| format!("--data: {e}")))
                .transpose()?;
            (
                api.call(http::Method::POST, &path, Some(&body.unwrap_or(json!({}))))
                    .await?,
                None,
            )
        }
        CtlCommand::Put { path, data } => {
            let body: Value = serde_json::from_str(&data).map_err(|e| format!("--data: {e}"))?;
            (api.call(http::Method::PUT, &path, Some(&body)).await?, None)
        }
        CtlCommand::Delete { path } => (api.call(http::Method::DELETE, &path, None).await?, None),
        CtlCommand::Simulate {
            file,
            window,
            until,
        } => {
            let text =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let config: Value = toml::from_str::<toml::Value>(&text)
                .map_err(|e| format!("{}: {e}", file.display()))
                .and_then(|t| serde_json::to_value(t).map_err(|e| e.to_string()))?;
            let body = json!({"config": config, "window": window, "until": until});
            (
                api.call(http::Method::POST, "simulate", Some(&body))
                    .await?,
                Some(Box::new(simulation_text) as Box<dyn Fn(&Value) -> String>),
            )
        }
        CtlCommand::Status => {
            let info = api.get("system/info").await?;
            let sum = api.get("stats/summary?from=-24h").await?;
            let v = json!({"system": info, "summary": sum});
            (
                v,
                Some(Box::new(|v: &Value| {
                    let i = &v["system"];
                    let su = &v["summary"];
                    format!(
                        "TelltaleDNS {} on {} (up {}s)\nlast 24 h: {} queries, {}% blocked, {}% from cache, {} clients\n",
                        s(i, "version"),
                        s(i, "node"),
                        s(i, "uptimeSeconds"),
                        s(su, "queries"),
                        s(su, "blockedPercent"),
                        s(su, "cacheHitPercent"),
                        s(su, "activeClients"),
                    )
                })),
            )
        }
        CtlCommand::Queries {
            name,
            client,
            status,
            from,
            limit,
        } => {
            let q = query(&[
                ("name", name),
                ("client", client),
                ("status", status),
                ("from", Some(from)),
                ("limit", Some(limit.to_string())),
            ]);
            (
                api.get(&format!("queries{q}")).await?,
                Some(Box::new(|v: &Value| {
                    let rows: Vec<Vec<String>> = items(v)
                        .iter()
                        .map(|r| {
                            let who = s(r, "clientName");
                            vec![
                                s(r, "time"),
                                if who.is_empty() { s(r, "client") } else { who },
                                s(r, "qtype"),
                                s(r, "name"),
                                s(r, "status"),
                                s(r, "list"),
                                format!("{} ms", s(r, "totalMs")),
                            ]
                        })
                        .collect();
                    table(
                        &["TIME", "CLIENT", "TYPE", "NAME", "STATUS", "LIST", "TOOK"],
                        &rows,
                    )
                })),
            )
        }
        CtlCommand::Top { kind, from, limit } => {
            let q = query(&[
                ("kind", Some(kind)),
                ("from", Some(from)),
                ("limit", Some(limit.to_string())),
            ]);
            (
                api.get(&format!("stats/top{q}")).await?,
                Some(Box::new(|v: &Value| {
                    let rows: Vec<Vec<String>> = items(v)
                        .iter()
                        .map(|r| {
                            let label = s(r, "name");
                            vec![
                                if label.is_empty() { s(r, "key") } else { label },
                                s(r, "count"),
                            ]
                        })
                        .collect();
                    table(&["NAME", "COUNT"], &rows)
                })),
            )
        }
        CtlCommand::Block(a) => (rule(&api, "block", a).await?, Some(Box::new(rule_done))),
        CtlCommand::Allow(a) => (rule(&api, "allow", a).await?, Some(Box::new(rule_done))),
        CtlCommand::Unrule { id } => (
            api.call(http::Method::DELETE, &format!("rules/{id}"), None)
                .await?,
            Some(Box::new(|_: &Value| "removed\n".to_owned())),
        ),
        CtlCommand::Rules => (
            api.get("rules").await?,
            Some(Box::new(|v: &Value| {
                let rows: Vec<Vec<String>> = items(v)
                    .iter()
                    .map(|r| {
                        vec![
                            s(r, "id"),
                            s(r, "action"),
                            s(r, "domain"),
                            s(r, "groups"),
                            s(r, "devices"),
                            s(r, "expires"),
                            s(r, "note"),
                        ]
                    })
                    .collect();
                table(
                    &[
                        "ID", "ACTION", "DOMAIN", "GROUPS", "DEVICES", "EXPIRES", "NOTE",
                    ],
                    &rows,
                )
            })),
        ),
        CtlCommand::Pause { minutes, group } => (
            api.call(
                http::Method::POST,
                "blocking/pause",
                Some(&json!({"minutes": minutes, "group": group})),
            )
            .await?,
            Some(Box::new(move |_: &Value| {
                format!("blocking paused for {minutes} minutes\n")
            })),
        ),
        CtlCommand::Resume { group } => (
            api.call(
                http::Method::POST,
                "blocking/resume",
                Some(&json!({"group": group})),
            )
            .await?,
            Some(Box::new(|_: &Value| "blocking resumed\n".to_owned())),
        ),
        // REQ: CLU-013
        CtlCommand::Rollout(c) => rollout(&api, c).await?,
        CtlCommand::Versions => (
            api.get("cluster/versions").await?,
            Some(Box::new(versions_text)),
        ),
        CtlCommand::Pin {
            version,
            reason,
            dry_run,
        } => (
            api.call(
                http::Method::POST,
                &format!(
                    "cluster/versions/{}/pin{}",
                    path_segment(&version),
                    if dry_run { "?dryRun=true" } else { "" }
                ),
                Some(&json!({ "reason": reason })),
            )
            .await?,
            Some(Box::new(action_text)),
        ),
        CtlCommand::Unpin { dry_run } => (
            api.call(
                http::Method::DELETE,
                &format!("cluster/pin{}", if dry_run { "?dryRun=true" } else { "" }),
                None,
            )
            .await?,
            Some(Box::new(action_text)),
        ),
        // REQ: CLU-001 (ADR-155)
        CtlCommand::Upgrade(a) => (upgrade(&api, a).await?, Some(Box::new(upgrade_text))),
        CtlCommand::RemoveNode {
            node,
            force,
            dry_run,
        } => (
            api.call(
                http::Method::DELETE,
                &format!(
                    "cluster/nodes/{}?force={force}&dryRun={dry_run}",
                    path_segment(&node)
                ),
                None,
            )
            .await?,
            Some(Box::new(removal_text)),
        ),
        // REQ: OPS-010
        CtlCommand::Maintenance(MaintenanceCmd::Start {
            for_secs,
            reason,
            node,
            no_handover,
        }) => (
            api.call(
                http::Method::POST,
                &format!("nodes/{}/maintenance", path_segment(&node)),
                Some(&json!({"forSecs": for_secs, "reason": reason, "handover": !no_handover})),
            )
            .await?,
            Some(Box::new(|v: &Value| {
                let w = &v["window"];
                let mut out = format!(
                    "{} is in maintenance until {} ({}): not ready for new traffic, still answering\n",
                    s(v, "node"),
                    s(w, "until"),
                    s(w, "reason")
                );
                match s(v, "handover").as_str() {
                    "started" => out.push_str("handing the primary role to another node (configuration changes pause for about 30 s)\n"),
                    _ if !s(v, "note").is_empty() => {
                        let _ = writeln!(out, "note: {}", s(v, "note"));
                    }
                    _ => {}
                }
                out
            })),
        ),
        CtlCommand::Maintenance(MaintenanceCmd::End { node }) => (
            api.call(
                http::Method::DELETE,
                &format!("nodes/{}/maintenance", path_segment(&node)),
                None,
            )
            .await?,
            Some(Box::new(|v: &Value| {
                let note = s(v, "note");
                if note.is_empty() {
                    format!(
                        "{}: maintenance ended; ready for traffic again\n",
                        s(v, "node")
                    )
                } else {
                    format!("{}: {note}\n", s(v, "node"))
                }
            })),
        ),
        CtlCommand::Maintenance(MaintenanceCmd::Status) => (
            api.get("system/health").await?,
            Some(Box::new(|v: &Value| {
                let rows: Vec<Vec<String>> = v["maintenance"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                    .iter()
                    .map(|m| vec![s(m, "node"), s(m, "until"), s(m, "reason"), s(m, "by")])
                    .collect();
                if rows.is_empty() {
                    "no node is in maintenance\n".to_owned()
                } else {
                    table(&["NODE", "UNTIL", "REASON", "BY"], &rows)
                }
            })),
        ),
        // REQ: CLU-014
        CtlCommand::Drill(DrillCmd::Start {
            for_secs,
            group,
            client,
            reason,
            node,
            dry_run,
            refused,
        }) => {
            let mode = if refused { "refused" } else { "drop" };
            let targets = match (group, client.is_empty()) {
                (Some(g), _) => json!({ "group": g }),
                (None, false) => json!({ "clients": client }),
                (None, true) => json!("all"),
            };
            (
                api.call(
                    http::Method::POST,
                    &format!(
                        "nodes/{}/drill{}",
                        path_segment(&node),
                        if dry_run { "?dryRun=true" } else { "" }
                    ),
                    Some(&json!({"forSecs": for_secs, "targets": targets, "reason": reason, "mode": mode})),
                )
                .await?,
                Some(Box::new(|v: &Value| {
                    let mut out = String::new();
                    for c in v["checks"]
                        .as_array()
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                    {
                        let ok = c["ok"].as_bool().unwrap_or(false);
                        let _ = writeln!(
                            out,
                            "{} {}",
                            if ok { "ok  " } else { "FAIL" },
                            s(c, "detail")
                        );
                    }
                    if v["dryRun"].as_bool().unwrap_or(false) {
                        let _ = writeln!(
                            out,
                            "would stop answering {} of the {} devices seen in the last hour: {}",
                            v["targetsResolved"],
                            v["baseline"],
                            v["devices"]
                                .as_array()
                                .map(Vec::as_slice)
                                .unwrap_or_default()
                                .iter()
                                .map(|d| d["name"]
                                    .as_str()
                                    .unwrap_or_else(|| d["client"].as_str().unwrap_or(""))
                                    .to_owned())
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    } else {
                        let _ = writeln!(
                            out,
                            "drill {} on {} until {}: {}\nthe report follows about a minute after it ends: telltale ctl drill report {}",
                            s(v, "id"),
                            s(v, "node"),
                            s(v, "until"),
                            s(v, "preview"),
                            s(v, "id")
                        );
                    }
                    out
                })),
            )
        }
        CtlCommand::Drill(DrillCmd::Stop { node }) => (
            api.call(
                http::Method::DELETE,
                &format!("nodes/{}/drill", path_segment(&node)),
                None,
            )
            .await?,
            Some(Box::new(|v: &Value| {
                format!("{}: {}\n", s(v, "node"), s(v, "preview"))
            })),
        ),
        CtlCommand::Drill(DrillCmd::Report { id: Some(id) }) => (
            api.get(&format!("drills/{}", path_segment(&id))).await?,
            Some(Box::new(|v: &Value| {
                let mut out = format!(
                    "{} on {}: {} followed, {} stuck, {} quiet; coverage {}\n",
                    s(v, "targets"),
                    s(v, "node"),
                    v["followed"],
                    v["stuck"],
                    v["quiet"],
                    v.get("coveragePercent")
                        .map_or_else(|| "–".to_owned(), |c| format!("{c} %"))
                );
                let rows: Vec<Vec<String>> = v["devices"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                    .iter()
                    .map(|d| {
                        vec![
                            d["name"]
                                .as_str()
                                .map_or_else(|| s(d, "client"), str::to_owned),
                            s(d, "verdict"),
                            d["dropped"].to_string(),
                            d.get("timeToFailoverMs")
                                .map_or_else(String::new, |t| format!("{t} ms")),
                            match d.get("returned").and_then(Value::as_bool) {
                                Some(true) => "came back".into(),
                                Some(false) => "stayed".into(),
                                None => String::new(),
                            },
                        ]
                    })
                    .collect();
                out.push_str(&table(
                    &["DEVICE", "VERDICT", "UNANSWERED", "FAILOVER", "AFTER"],
                    &rows,
                ));
                out
            })),
        ),
        CtlCommand::Drill(DrillCmd::Report { id: None }) => (
            api.get("drills?limit=10").await?,
            Some(Box::new(|v: &Value| {
                let rows: Vec<Vec<String>> = v["items"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                    .iter()
                    .map(|d| {
                        vec![
                            s(d, "id"),
                            s(d, "node"),
                            s(d, "since"),
                            s(d, "targets"),
                            s(d, "status"),
                            d.get("coveragePercent")
                                .map_or_else(String::new, |c| format!("{c} %")),
                            d["stuck"].to_string(),
                        ]
                    })
                    .collect();
                if rows.is_empty() {
                    "no drills yet\n".to_owned()
                } else {
                    table(
                        &[
                            "ID", "NODE", "SINCE", "TARGETS", "STATUS", "COVERAGE", "STUCK",
                        ],
                        &rows,
                    )
                }
            })),
        ),
        CtlCommand::Flush { name, subtree } => (
            api.call(
                http::Method::POST,
                "cache/flush",
                Some(&json!({"name": name, "subtree": subtree})),
            )
            .await?,
            Some(Box::new(|v: &Value| {
                format!(
                    "flushed{}\n",
                    v.get("removed")
                        .map_or_else(String::new, |n| format!(" {n} entries"))
                )
            })),
        ),
        CtlCommand::Explain { name, client } => (
            api.get(&format!(
                "explain{}",
                query(&[("name", Some(name)), ("client", client)])
            ))
            .await?,
            Some(Box::new(|v: &Value| format!("{}\n", s(v, "summary")))),
        ),
        CtlCommand::Lists => (
            api.get("lists").await?,
            Some(Box::new(|v: &Value| {
                let rows: Vec<Vec<String>> = items(v)
                    .iter()
                    .map(|r| {
                        vec![
                            s(r, "name"),
                            s(r, "kind"),
                            s(r, "state"),
                            s(r, "entries"),
                            s(r, "unique"),
                            s(r, "hits"),
                        ]
                    })
                    .collect();
                table(&["LIST", "KIND", "STATE", "NAMES", "UNIQUE", "HITS"], &rows)
            })),
        ),
        CtlCommand::Groups => {
            named(&api, "groups", &["name", "lists", "blockMode", "networks"]).await?
        }
        CtlCommand::Clients => named(&api, "clients", &["name", "match", "groups"]).await?,
        CtlCommand::Upstreams => {
            named(
                &api,
                "upstreams",
                &["name", "endpoint", "breaker", "latencyEwmaMs"],
            )
            .await?
        }
        CtlCommand::Anomalies { since } => (
            api.get(&format!(
                "analytics/anomalies{}",
                query(&[("since", Some(since))])
            ))
            .await?,
            Some(Box::new(|v: &Value| {
                let rows: Vec<Vec<String>> = items(v)
                    .iter()
                    .map(|r| {
                        let who = s(r, "clientName");
                        vec![
                            s(r, "windowStart"),
                            if who.is_empty() { s(r, "client") } else { who },
                            s(r, "kind"),
                            s(r, "detail"),
                        ]
                    })
                    .collect();
                table(&["WHEN", "DEVICE", "KIND", "DETAIL"], &rows)
            })),
        ),
        CtlCommand::Plans => {
            named(&api, "plans", &["id", "state", "tool", "summary", "reason"]).await?
        }
        CtlCommand::Approve { id } => (
            api.call(
                http::Method::POST,
                &format!("plans/{id}/approve"),
                Some(&json!({})),
            )
            .await?,
            Some(Box::new(|_: &Value| {
                "approved: the agent can apply it now\n".to_owned()
            })),
        ),
        CtlCommand::Reject { id } => (
            api.call(
                http::Method::POST,
                &format!("plans/{id}/reject"),
                Some(&json!({})),
            )
            .await?,
            Some(Box::new(|_: &Value| "rejected\n".to_owned())),
        ),
    };
    Ok(match render {
        Some(r) if !json_out => r(&v),
        _ => format!("{}\n", pretty(&v)),
    })
}

type Rendered = (Value, Option<Box<dyn Fn(&Value) -> String>>);

/// REQ: OPS-014 — one node to upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UpgradeStep {
    id: String,
    label: String,
    from: String,
    primary: bool,
}

/// REQ: OPS-014 — who gets the version, in order, and who doesn't and why.
#[derive(Debug, Default, PartialEq, Eq)]
struct UpgradePlan {
    steps: Vec<UpgradeStep>,
    skipped: Vec<(String, String)>,
    down: Vec<String>,
}

/// REQ: OPS-014, CLU-010 — the order from a cluster view (`GET /cluster`): native replicas
/// first (by site, then ID), the primary last; pods are the chart's, witnesses only vote (they
/// answer nothing else, so they are upgraded by hand), and nodes already on the version (or
/// newer, or on a local build) are left alone. A member the cluster has never heard from (no
/// version) is down. `only` keeps the nodes named.
fn upgrade_plan(view: &Value, to: &str, only: &[String]) -> UpgradePlan {
    use telltale_api::update_api::version_key;
    let mut plan = UpgradePlan::default();
    let want = version_key(to);
    let mut steps = Vec::new();
    for n in arr(&view["nodes"]) {
        let (id, site, pod) = (s(n, "nodeId"), s(n, "site"), s(n, "pod"));
        if !only.is_empty() && !only.iter().any(|o| *o == id || *o == site || *o == pod) {
            continue;
        }
        let label = match (pod.is_empty(), site.is_empty()) {
            (false, _) => pod.clone(),
            (true, false) => format!("{site} ({id})"),
            (true, true) => id.clone(),
        };
        let version = s(n, "version");
        let have = version_key(&version);
        let reason = if n["ephemeral"].as_bool() == Some(true) || !pod.is_empty() {
            Some("a Kubernetes pod: the chart upgrades it".to_owned())
        } else if n["witness"].as_bool() == Some(true) {
            // REQ: OPS-014 (ADR-182) — a witness answers only votes ("a witness only votes").
            Some("a witness: upgrade it by hand (telltale self-update)".to_owned())
        } else if version.is_empty() {
            // Listed in the registry, never heard from since this node started: down.
            plan.down.push(label);
            continue;
        } else if version == to {
            Some(format!("already on {to}"))
        } else if have.is_none() {
            Some(format!("a local build ({version})"))
        } else if have > want {
            Some(format!("runs {version}, newer than {to}"))
        } else {
            None
        };
        if let Some(r) = reason {
            plan.skipped.push((label, r));
        } else if n["up"].as_bool() != Some(true) {
            plan.down.push(label);
        } else {
            steps.push((
                s(n, "role") == "primary",
                site,
                id.clone(),
                UpgradeStep {
                    id,
                    label,
                    from: version,
                    primary: false,
                },
            ));
        }
    }
    steps.sort_by(|a, b| (a.0, &a.1, &a.2).cmp(&(b.0, &b.1, &b.2)));
    plan.steps = steps
        .into_iter()
        .map(|(primary, _, _, step)| UpgradeStep { primary, ..step })
        .collect();
    plan
}

/// REQ: OPS-014 (ADR-182) — what the pre-flight read of a planned node (`GET …/update`) says.
#[derive(Debug, PartialEq, Eq)]
enum Preflight {
    /// It can take the request.
    Ready,
    /// Not the cluster's to upgrade (a container): left alone, as pods are.
    Leave(String),
    /// It can't take a request now: the run stops before asking anyone (`--skip-down` leaves it
    /// out instead).
    Block(String),
}

/// How long an `installing` run counts as running (the node's own lock).
const INSTALLING_MS: u64 = crate::node_update::RUNNING_MS;

/// REQ: OPS-014 (ADR-182) — `ctl upgrade --timeout`'s default: at least the root update service's
/// longest run (`node_update::run_budget_secs`, checked by a test), so `ctl` and the chart's hook
/// don't give up on a node that is still within its time.
pub(crate) const UPGRADE_TIMEOUT: &str = "15m";

/// REQ: OPS-014 (ADR-182) — whether a node whose update state is `u` can be asked for `to` now
/// (`now_ms`: this machine's clock, for the age of a run that says `installing`).
fn preflight(u: &Value, to: &str, now_ms: u64) -> Preflight {
    let install = s(u, "install");
    if install != "native" {
        return Preflight::Leave(format!(
            "installed as {}: its image is upgraded by its deployment",
            if install.is_empty() {
                "unknown"
            } else {
                &install
            }
        ));
    }
    if u["enabled"].as_bool() != Some(true) {
        return Preflight::Block(
            "its update service is off (on the node, as root: systemctl enable --now telltale-update.path)"
                .into(),
        );
    }
    if u["pending"].is_object() {
        return Preflight::Block(format!(
            "a request for {} is already waiting for its update service",
            s(&u["pending"], "to")
        ));
    }
    let last = &u["last"];
    if s(last, "state") == "installing" {
        let at = telltale_api::time::parse_time_ms(&s(last, "at"), now_ms).unwrap_or(now_ms);
        if now_ms.saturating_sub(at) < INSTALLING_MS {
            return Preflight::Block(format!("an update to {} is running on it", s(last, "to")));
        }
    }
    // REQ: OPS-014 (ADR-182) — the node holds this version back (its new build was installed
    // there and didn't come up, within the last day: `update_failed_recently`), by its own record
    // and clock: stop before any node is asked. A run that failed before installing anything
    // holds nothing back, so it doesn't stop the run.
    let held = &u["held"];
    if s(held, "to") == to {
        return Preflight::Block(format!(
            "it holds {to} back until {}: {}",
            s(held, "until"),
            s(held, "why")
        ));
    }
    // REQ: OPS-014 (ADR-182) — said in full: which channel the node follows, what was asked, and
    // how to change it (a node set up wrong, never mistaken for one that is down).
    let channel = telltale_api::update_api::node_channel(u["channel"].as_str(), &s(u, "version"));
    if let Err(why) = telltale_api::update_api::channel_takes(channel, to) {
        return Preflight::Block(format!(
            "CHANNEL: it runs {} and {why} ({})",
            s(u, "version"),
            telltale_api::update_api::CHANNEL_HINT
        ));
    }
    Preflight::Ready
}

/// The hint for an entry node that answers a bare 404 for the update route: it is older.
const OLDER_ENTRY: &str = "the node at --url doesn't have updates from the cluster (it runs an older version): upgrade it by hand first (as root on it: telltale self-update --restart, or with --channel edge for a node on edge builds), or point --url at a node that does";

/// REQ: OPS-014 (ADR-182) — `--skip-if-unreachable` skips only a first install: the API's name
/// doesn't exist yet (`no_such_name`: the chart's Service isn't there), or every address of it
/// refused the connection (nothing listens yet). Anything else (a lookup that failed another way,
/// a timeout, packets dropped, an address that answers, so the failure was TLS or HTTP) is no
/// first install. What it found, or `None`.
fn first_install(
    no_such_name: bool,
    connects: &[Result<(), std::io::ErrorKind>],
) -> Option<&'static str> {
    if no_such_name {
        return Some("its name doesn't resolve");
    }
    (!connects.is_empty()
        && connects
            .iter()
            .all(|c| *c == Err(std::io::ErrorKind::ConnectionRefused)))
    .then_some("nothing listens at its address")
}

/// A name lookup that failed because the name doesn't exist (glibc: "Name or service not known";
/// musl, the image's: "Name does not resolve"), not because the lookup itself failed.
fn no_such_name(e: &std::io::Error) -> bool {
    let m = e.to_string();
    [
        "Name or service not known",
        "Name does not resolve",
        "No address associated with hostname",
    ]
    .iter()
    .any(|n| m.contains(n))
}

/// For [`first_install`]: whether the host of `base` has no such name, and else what a TCP
/// connection to each of its addresses did (bounded: 10 s for the lookup, 5 s per address).
async fn look_at(base: &str) -> (bool, Vec<Result<(), std::io::ErrorKind>>) {
    use std::time::Duration;
    let Ok(uri) = base.parse::<http::Uri>() else {
        return (false, Vec::new());
    };
    let Some(host) = uri.host() else {
        return (false, Vec::new());
    };
    let name = host.trim_start_matches('[').trim_end_matches(']');
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let addrs: Vec<std::net::SocketAddr> = match name.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![std::net::SocketAddr::new(ip, port)],
        Err(_) => match tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::lookup_host((name, port)),
        )
        .await
        {
            Ok(Ok(a)) => a.collect(),
            Ok(Err(e)) => return (no_such_name(&e), Vec::new()),
            Err(_) => return (false, Vec::new()),
        },
    };
    let mut out = Vec::new();
    for a in addrs {
        out.push(
            match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(a))
                .await
            {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(e.kind()),
                Err(_) => Err(std::io::ErrorKind::TimedOut),
            },
        );
    }
    (false, out)
}

/// A problem answer as one line: its detail and hint (an older node's bare 404 gets a hint).
fn problem_line(status: http::StatusCode, p: &Value) -> String {
    let code = s(p, "code");
    if status == http::StatusCode::NOT_FOUND && (code.is_empty() || code == "not_found") {
        return format!("HTTP {status}: {OLDER_ENTRY}");
    }
    format!(
        "HTTP {status}: {}{}",
        s(p, "detail"),
        p.get("hint")
            .and_then(Value::as_str)
            .map_or_else(String::new, |h| format!(" ({h})"))
    )
}

/// REQ: OPS-014 — whether `node` in a cluster view runs `to`, is up and ready, and has the
/// newest configuration.
fn upgraded(view: &Value, id: &str, to: &str) -> bool {
    arr(&view["nodes"]).iter().any(|n| {
        s(n, "nodeId") == id
            && s(n, "version") == to
            && n["up"].as_bool() == Some(true)
            && n["ready"].as_bool() != Some(false)
            && n["configLag"].as_u64().unwrap_or(0) == 0
    })
}

/// REQ: OPS-014 — `telltale ctl upgrade`: the plan, then each node in turn; progress on stderr.
#[allow(clippy::too_many_lines)] // one sequence: plan, ask, wait, report
async fn upgrade(api: &Api, a: UpgradeArgs) -> Result<Value, String> {
    let to = match (&a.to, a.to_self) {
        (Some(v), _) => v.clone(),
        (None, _) => crate::build_info::VERSION.to_owned(),
    };
    let to = telltale_api::update_api::check_version(&to).map_err(|p| {
        if a.to_self {
            format!("this binary is a local build ({to}), not a release: pass --to")
        } else {
            p.detail
        }
    })?;
    // REQ: OPS-014, AGT-003 — every request says why (an agent token's change must).
    let api = &api.with_reason(
        a.reason
            .clone()
            .unwrap_or_else(|| format!("telltale ctl upgrade --to {to}")),
    );
    let view = match api.call_raw(http::Method::GET, "cluster", None).await {
        Ok(Ok(v)) => v,
        Ok(Err((status, v))) => {
            return Err(format!("GET /cluster: HTTP {status}: {}", s(&v, "detail")));
        }
        Err(e) if a.skip_if_unreachable => {
            // REQ: OPS-014 (ADR-182) — only a first install is skipped: the API's name doesn't
            // resolve yet, or nothing listens at its address. A timeout, a TLS failure, or packets
            // a policy drops fail the run (they hide an upgrade's order, not a first install).
            let (no_name, connects) = look_at(&api.base).await;
            let Some(what) = first_install(no_name, &connects) else {
                return Err(format!(
                    "{e} (--skip-if-unreachable skips only a first install, where the API's name doesn't resolve or nothing listens at its address yet; this is something else)"
                ));
            };
            // Loud: on an upgrade this lets the chart's pods roll before the native nodes.
            eprintln!(
                "WARNING: nothing answered at the API ({what}: {e}), so no node was asked to \
                 upgrade (--skip-if-unreachable). Expected on a first install; on an upgrade the \
                 chart's pods now roll before the native nodes: check the API Service and run \
                 `telltale ctl upgrade --to {to}` by hand."
            );
            return Ok(
                json!({"to": to, "upgraded": [], "skipped": [], "note": format!("nothing to upgrade yet ({what}): {e}")}),
            );
        }
        Err(e) => return Err(e),
    };
    let mut plan = if view["enabled"].as_bool() == Some(true) {
        upgrade_plan(&view, &to, &a.nodes)
    } else {
        // A standalone node: itself.
        let info = api.get("system/info").await?;
        let version = s(&info, "version");
        let mut p = UpgradePlan::default();
        if version == to {
            p.skipped
                .push(("this node".into(), format!("already on {to}")));
        } else {
            p.steps.push(UpgradeStep {
                id: "local".into(),
                label: "this node".into(),
                from: version,
                primary: true,
            });
        }
        p
    };
    if !plan.down.is_empty() {
        if !a.skip_down {
            return Err(format!(
                "{} {} down: replicas go first, so nothing was upgraded. Start {}, remove a node that is gone for good (telltale ctl remove-node), or pass --skip-down",
                plan.down.join(", "),
                if plan.down.len() == 1 { "is" } else { "are" },
                if plan.down.len() == 1 { "it" } else { "them" }
            ));
        }
        for d in std::mem::take(&mut plan.down) {
            plan.skipped.push((d, "down (--skip-down)".into()));
        }
    }
    // REQ: OPS-014 (ADR-182) — pre-flight: every planned node is read before any is asked, so a
    // node that couldn't take the request stops the run with nothing asked (one at a time,
    // replicas first, holds only if every one of them can go).
    let now_ms = crate::maintenance::now_ms();
    let mut blocked: Vec<(String, String)> = Vec::new();
    let mut ready = Vec::new();
    for st in std::mem::take(&mut plan.steps) {
        let path = format!("nodes/{}/update", path_segment(&st.id));
        let read = match api.call_raw(http::Method::GET, &path, None).await {
            Err(e) => Err(format!("not reachable: {e}")),
            Ok(Err((status, p))) => Err(problem_line(status, &p)),
            Ok(Ok(u)) => Ok(preflight(&u, &to, now_ms)),
        };
        match read {
            Ok(Preflight::Ready) => ready.push(st),
            Ok(Preflight::Leave(why)) => plan.skipped.push((st.label, why)),
            Ok(Preflight::Block(why)) | Err(why) => blocked.push((st.label, why)),
        }
    }
    plan.steps = ready;
    // REQ: OPS-014 (ADR-182) — a node that is up but can't take the request is set up wrong (its
    // update service off, another channel, a run under way, a version it refuses for a day): it
    // stops the run, with --skip-down too (that skips only nodes that are down).
    if !blocked.is_empty() && !a.dry_run {
        let list: Vec<String> = blocked.iter().map(|(n, w)| format!("{n}: {w}")).collect();
        return Err(format!(
            "nothing was asked: {} can't take the upgrade now ({}); fix {} first (--skip-down skips only nodes that are down)",
            if blocked.len() == 1 {
                "a node"
            } else {
                "nodes"
            },
            list.join("; "),
            if blocked.len() == 1 { "it" } else { "them" }
        ));
    }
    let skipped: Vec<Value> = plan
        .skipped
        .iter()
        .map(|(n, r)| json!({"node": n, "reason": r}))
        .collect();
    if a.dry_run {
        let order: Vec<Value> = plan
            .steps
            .iter()
            .map(|st| json!({"node": st.label, "from": st.from, "primary": st.primary}))
            .collect();
        let blocked: Vec<Value> = blocked
            .iter()
            .map(|(n, r)| json!({"node": n, "reason": r}))
            .collect();
        return Ok(
            json!({"to": to, "dryRun": true, "order": order, "skipped": skipped, "blocked": blocked}),
        );
    }
    let mut done = Vec::new();
    let mut skipped = skipped;
    let timeout = std::time::Duration::from_secs(u64::from(a.timeout));
    'nodes: for st in &plan.steps {
        let path = format!("nodes/{}/update", path_segment(&st.id));
        eprintln!(
            "{}: asking it to install {to} (it runs {})",
            st.label, st.from
        );
        let started = std::time::Instant::now();
        let r = match api
            .call_raw(http::Method::POST, &path, Some(&json!({"to": to})))
            .await?
        {
            Ok(v) => v,
            Err((_, p)) if s(&p, "code") == "update_unsupported" => {
                eprintln!("{}: {}", st.label, s(&p, "detail"));
                skipped.push(json!({"node": st.label, "reason": s(&p, "detail")}));
                continue;
            }
            Err((status, p)) => {
                return Err(format!("{}: {}", st.label, problem_line(status, &p)));
            }
        };
        if s(&r, "state") == "up_to_date" {
            skipped.push(json!({"node": st.label, "reason": format!("already on {to}")}));
            continue;
        }
        let id = r["pending"]["id"].as_str().unwrap_or_default().to_owned();
        if id.is_empty() {
            return Err(format!(
                "{}: the node didn't say which request it wrote, so its outcome can't be followed: ask it again, or upgrade it by hand",
                st.label
            ));
        }
        // REQ: OPS-014 (ADR-182) — done only once the update service has recorded `updated` for
        // this request (after its health gate) and the cluster view shows the node on the
        // version, ready and in sync: a rollback inside the gate stops the run.
        let mut updated = false;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let waited = started.elapsed();
            // The node restarts (and with it, for the primary, the API): failures are expected.
            if let Ok(u) = api.get(&path).await {
                let last = &u["last"];
                if s(last, "id") == id {
                    match s(last, "state").as_str() {
                        "updated" => updated = true,
                        "up_to_date" => {
                            skipped.push(
                                json!({"node": st.label, "reason": format!("already on {to}")}),
                            );
                            continue 'nodes;
                        }
                        // REQ: OPS-014 (ADR-182) — the build can't be fetched any more: with
                        // --skip-unavailable the node keeps its version and the run goes on.
                        "unavailable" if a.skip_unavailable => {
                            eprintln!(
                                "WARNING: {}: {}. Left on {} (--skip-unavailable): the order isn't kept for it in this run, so the chart's pods may now run a newer build than this native node.",
                                st.label,
                                s(last, "error"),
                                st.from
                            );
                            skipped.push(json!({"node": st.label, "reason": format!(
                                "{to} can't be fetched any more (--skip-unavailable): {}",
                                s(last, "error")
                            )}));
                            continue 'nodes;
                        }
                        "unavailable" => {
                            return Err(format!(
                                "{}: {to} can't be fetched any more: {} (--skip-unavailable, or the chart's upgradeHook.whenUnavailable: skip, leaves such a node on its version and goes on)",
                                st.label,
                                s(last, "error")
                            ));
                        }
                        // REQ: OPS-014 (ADR-182) — a rollback is a failure: the run stops.
                        "failed" | "refused" | "rolled_back" => {
                            return Err(format!(
                                "{}: {} {to}: {}",
                                st.label,
                                s(last, "state"),
                                s(last, "error")
                            ));
                        }
                        _ => {}
                    }
                } else if s(&u["pending"], "id") == id
                    && waited > std::time::Duration::from_secs(60)
                {
                    return Err(format!(
                        "{}: its update service hasn't picked the request up in a minute: check telltale-update.path and `journalctl -u telltale-update` on the node",
                        st.label
                    ));
                }
            }
            let caught_up = updated
                && if st.id == "local" {
                    api.get("system/info")
                        .await
                        .is_ok_and(|i| s(&i, "version") == to)
                } else {
                    api.get("cluster")
                        .await
                        .is_ok_and(|v| upgraded(&v, &st.id, &to))
                };
            if caught_up {
                let secs = started.elapsed().as_secs();
                eprintln!("{}: on {to}, ready and in sync ({secs} s)", st.label);
                done.push(json!({"node": st.label, "from": st.from, "to": to, "seconds": secs}));
                break;
            }
            if waited > timeout {
                return Err(format!(
                    "{}: {} after {} s: the nodes after it were not upgraded",
                    st.label,
                    if updated {
                        format!("not back on {to}, ready and in sync")
                    } else {
                        format!("its update service hasn't recorded {to} as installed and healthy")
                    },
                    timeout.as_secs()
                ));
            }
        }
    }
    Ok(json!({"to": to, "upgraded": done, "skipped": skipped}))
}

/// REQ: OPS-014 — what `ctl upgrade` did (or would do) as text.
fn upgrade_text(v: &Value) -> String {
    let mut out = String::new();
    let to = s(v, "to");
    if let Some(note) = v["note"].as_str() {
        let _ = writeln!(out, "Nothing to upgrade to {to}: {note}");
        return out;
    }
    if v["dryRun"].as_bool() == Some(true) {
        if arr(&v["order"]).is_empty() {
            let _ = writeln!(out, "No node needs {to}.");
        } else {
            let _ = writeln!(out, "Would upgrade to {to}, in this order:");
        }
        for (i, n) in arr(&v["order"]).iter().enumerate() {
            let _ = writeln!(
                out,
                "  {}. {} (now {}){}",
                i + 1,
                s(n, "node"),
                s(n, "from"),
                if n["primary"].as_bool() == Some(true) {
                    ", the primary"
                } else {
                    ""
                }
            );
        }
    } else if arr(&v["upgraded"]).is_empty() {
        let _ = writeln!(out, "No node needed {to}.");
    } else {
        let _ = writeln!(out, "Upgraded to {to}:");
        for n in arr(&v["upgraded"]) {
            let _ = writeln!(
                out,
                "  {} (was {}, {} s)",
                s(n, "node"),
                s(n, "from"),
                s(n, "seconds")
            );
        }
    }
    for n in arr(&v["skipped"]) {
        let _ = writeln!(out, "  left alone: {}: {}", s(n, "node"), s(n, "reason"));
    }
    if !arr(&v["blocked"]).is_empty() {
        let _ = writeln!(
            out,
            "Would stop before asking any node (--skip-down leaves these out):"
        );
        for n in arr(&v["blocked"]) {
            let _ = writeln!(out, "  {}: {}", s(n, "node"), s(n, "reason"));
        }
    }
    out
}

/// A JSON array's items (none for anything else).
fn arr(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

/// REQ: OBS-024 — a simulation as text: the counts, then the top names of each kind.
fn simulation_text(v: &Value) -> String {
    let mut out = String::new();
    if v["available"] == Value::Bool(false) {
        let _ = writeln!(out, "not simulated: {}", s(v, "reason"));
        return out;
    }
    if v["applicable"] == Value::Bool(false) {
        out.push_str("nothing to simulate: the change can't affect how queries are answered\n");
        return out;
    }
    let _ = writeln!(
        out,
        "{} logged queries from {} to {}{}",
        s(v, "rows"),
        s(v, "from"),
        s(v, "to"),
        if v["partial"] == Value::Bool(true) {
            " (partial: the row or time bound was reached)"
        } else {
            ""
        }
    );
    let classes = [
        ("newlyBlocked", "newly blocked"),
        ("newlyAllowed", "newly allowed"),
        ("changedRoute", "changed route"),
        ("changedAnswer", "changed answer"),
    ];
    let rows: Vec<Vec<String>> = classes
        .iter()
        .map(|(k, label)| {
            vec![
                (*label).to_owned(),
                s(&v[*k], "queries"),
                s(&v[*k], "devices"),
            ]
        })
        .chain([vec![
            "unchanged".to_owned(),
            s(v, "unchanged"),
            String::new(),
        ]])
        .collect();
    out.push_str(&table(&["", "QUERIES", "DEVICES"], &rows));
    for (k, label) in classes {
        let names = v[k]["topNames"].as_array().map_or(&[][..], Vec::as_slice);
        if names.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n{label}:");
        let rows: Vec<Vec<String>> = names
            .iter()
            .map(|n| vec![s(n, "name"), s(n, "queries"), s(n, "devices"), s(n, "list")])
            .collect();
        out.push_str(&table(&["NAME", "QUERIES", "DEVICES", "BY"], &rows));
    }
    for k in ["notes", "missingNodes"] {
        let t = s(v, k);
        if !t.is_empty() {
            let _ = writeln!(out, "\n{k}: {t}");
        }
    }
    out
}

/// REQ: CLU-013 — `rollout status|promote|abort`.
async fn rollout(api: &Api, c: RolloutCmd) -> Result<Rendered, String> {
    Ok(match c {
        RolloutCmd::Status => (
            api.get("cluster/rollout").await?,
            Some(Box::new(rollout_text)),
        ),
        RolloutCmd::Promote => (
            api.call(
                http::Method::POST,
                "cluster/rollout/promote",
                Some(&json!({})),
            )
            .await?,
            Some(Box::new(action_text)),
        ),
        RolloutCmd::Abort => (
            api.call(
                http::Method::POST,
                "cluster/rollout/abort",
                Some(&json!({})),
            )
            .await?,
            Some(Box::new(action_text)),
        ),
    })
}

/// REQ: CLU-013 — a rollout status as text.
#[allow(clippy::too_many_lines)] // stage, guard, pin, then the nodes
fn rollout_text(v: &Value) -> String {
    let mut out = String::new();
    let canaries = s(v, "canaries");
    let _ = writeln!(
        out,
        "stable version {}; canaries: {}",
        s(v, "stable"),
        if canaries.is_empty() {
            "none (changes reach every node at once)".to_owned()
        } else {
            canaries
        }
    );
    match s(v, "stage").as_str() {
        "canary" => {
            let _ = writeln!(
                out,
                "version {} bakes on {} and the primary: {} s left (until {})",
                s(v, "version"),
                s(v, "rolloutCanaries"),
                s(v, "secondsLeft"),
                s(v, "bakeEnds")
            );
        }
        "waiting" => {
            let _ = writeln!(
                out,
                "a change waits for a canary node to come online (since {})",
                s(v, "waitingSince")
            );
        }
        _ => {}
    }
    if let Some(r) = v.get("readings").filter(|r| !r.is_null()) {
        let pct = |k: &str| {
            r.get(k)
                .and_then(Value::as_f64)
                .map_or_else(|| "-".to_owned(), |x| format!("{x:.1}%"))
        };
        let _ = writeln!(
            out,
            "guard: SERVFAIL {} before, {} during ({} answers){}",
            pct("beforePercent"),
            pct("afterPercent"),
            s(r, "answers"),
            r.get("reason")
                .and_then(Value::as_str)
                .map_or_else(String::new, |x| format!(": {x}"))
        );
    }
    if let Some(p) = v.get("pinned").filter(|p| !p.is_null()) {
        let _ = writeln!(
            out,
            "PINNED to version {} since {} by {}: {}",
            s(p, "to"),
            s(p, "since"),
            s(p, "by"),
            s(p, "reason")
        );
        let changes = s(p, "changes");
        if !changes.is_empty() {
            let _ = writeln!(out, "held back: {changes}");
        }
    }
    if let Some(skipped) = v.get("skipped").and_then(Value::as_str) {
        let _ = writeln!(out, "last change went to every node at once: {skipped}");
    }
    let rows: Vec<Vec<String>> = v["nodes"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|n| {
            vec![
                s(n, "node"),
                s(n, "site"),
                if n["canary"] == Value::Bool(true) {
                    "canary"
                } else {
                    ""
                }
                .to_owned(),
                s(n, "appliedSeq"),
                if n["connected"] == Value::Bool(false) {
                    "gone"
                } else if n["ready"] == Value::Bool(true) {
                    "ready"
                } else {
                    "not ready"
                }
                .to_owned(),
                format!("{}%", s(n, "servfailPercent")),
            ]
        })
        .collect();
    if !rows.is_empty() {
        out.push_str(&table(
            &["NODE", "SITE", "", "RUNS", "STATE", "SERVFAIL"],
            &rows,
        ));
    }
    out
}

/// REQ: CLU-013 — the kept versions as a table.
fn versions_text(v: &Value) -> String {
    let rows: Vec<Vec<String>> = items(v)
        .iter()
        .map(|r| {
            let mut outcome = s(r, "outcome");
            if !s(r, "pinnedTo").is_empty() {
                outcome = format!("{outcome} {}", s(r, "pinnedTo"));
            }
            vec![
                format!(
                    "{}{}",
                    s(r, "version"),
                    if r["current"] == Value::Bool(true) {
                        " *"
                    } else {
                        ""
                    }
                ),
                s(r, "created"),
                outcome,
                s(r, "by"),
                if r["pinnable"] == Value::Bool(true) {
                    "yes"
                } else {
                    "no"
                }
                .to_owned(),
            ]
        })
        .collect();
    table(&["VERSION", "CREATED", "OUTCOME", "BY", "PINNABLE"], &rows)
}

/// REQ: CLU-013 — what a rollout or pin action did.
/// REQ: CLU-001 (ADR-155) — what removing a node did, or would do.
fn removal_text(v: &Value) -> String {
    let done = v["removed"] == Value::Bool(true);
    let site = s(v, "site");
    let mut out = format!(
        "{} {}{}: {} voter(s) left, automatic failover {}\n",
        if done {
            "removed"
        } else {
            "dry run: would remove"
        },
        s(v, "nodeId"),
        if site.is_empty() {
            String::new()
        } else {
            format!(" (site {site})")
        },
        v["votersAfter"],
        if v["automaticFailoverAfter"] == Value::Bool(true) {
            "still on"
        } else {
            "off"
        },
    );
    if let Some(notes) = v["notes"].as_array() {
        for n in notes.iter().filter_map(Value::as_str) {
            let _ = writeln!(out, "note: {n}");
        }
    }
    out
}

fn action_text(v: &Value) -> String {
    let mut out = format!(
        "{}{}
",
        if v["dryRun"] == Value::Bool(true) {
            "dry run: "
        } else {
            ""
        },
        s(v, "done")
    );
    let changes = s(v, "changes");
    if !changes.is_empty() {
        let _ = writeln!(out, "changes: {changes}");
    }
    out
}

fn rule_done(v: &Value) -> String {
    if v.get("dryRun").and_then(Value::as_bool) == Some(true) {
        format!("dry run: {}\n", s(v, "summary"))
    } else {
        format!("done: {}\n", s(v, "summary"))
    }
}

async fn rule(api: &Api, action: &str, a: RuleArgs) -> Result<Value, String> {
    let id = rule_id(action, &a.domain);
    let body = json!({
        "action": action,
        "domain": a.domain,
        "forMinutes": a.minutes,
        "groups": a.groups,
        "devices": a.devices,
        "note": a.note,
    });
    let path = format!("rules/{id}{}", if a.dry_run { "?dryRun=true" } else { "" });
    api.call(http::Method::PUT, &path, Some(&body)).await
}

/// A list endpoint shown as a table of `cols`.
async fn named(
    api: &Api,
    path: &'static str,
    cols: &'static [&'static str],
) -> Result<Rendered, String> {
    let v = api.get(path).await?;
    Ok((
        v,
        Some(Box::new(move |v: &Value| {
            let rows: Vec<Vec<String>> = items(v)
                .iter()
                .map(|r| cols.iter().map(|c| s(r, c)).collect())
                .collect();
            let head: Vec<String> = cols.iter().map(|c| c.to_ascii_uppercase()).collect();
            let head: Vec<&str> = head.iter().map(String::as_str).collect();
            table(&head, &rows)
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: API-008 — paths, queries, IDs, and tables.
    #[test]
    fn api_008_helpers() {
        assert_eq!(
            query(&[("name", Some("a b&c".into())), ("x", None)]),
            "?name=a%20b%26c"
        );
        assert_eq!(
            rule_id("block", "Ads.Example.com."),
            "block-ads-example-com"
        );
        let t = table(&["A", "BB"], &[vec!["xyz".into(), "1".into()]]);
        assert_eq!(t, "A    BB\nxyz  1\n");
        let api = Api {
            client: telltale_filter::fetch::Client::new(
                Arc::new(telltale_filter::fetch::SystemResolver),
                &[],
            )
            .unwrap(),
            base: "http://127.0.0.1:8053/".into(),
            token: String::new(),
            reason: None,
        };
        assert_eq!(api.url("lists"), "http://127.0.0.1:8053/api/v1/lists");
        assert_eq!(
            api.url("/api/v1/stats/top?kind=blocked"),
            "http://127.0.0.1:8053/api/v1/stats/top?kind=blocked"
        );
    }

    /// REQ: OPS-010 — `--for` takes seconds or a unit; node names go into the path safely.
    #[test]
    fn ops_010_ctl_durations_and_node_paths() {
        assert_eq!(parse_duration("2h"), Ok(7200));
        assert_eq!(parse_duration("30m"), Ok(1800));
        assert_eq!(parse_duration("90s"), Ok(90));
        assert_eq!(parse_duration("1d"), Ok(86_400));
        assert_eq!(parse_duration("600"), Ok(600));
        assert!(parse_duration("2w").is_err() && parse_duration("h").is_err());
        assert_eq!(path_segment("telltale-0"), "telltale-0");
        assert_eq!(path_segment("a/b c"), "a%2Fb%20c");
    }

    fn node(id: &str, site: &str, role: &str, version: &str, up: bool, pod: Option<&str>) -> Value {
        json!({"nodeId": id, "site": site, "role": role, "version": version, "up": up,
               "ready": true, "configLag": 0, "ephemeral": false, "pod": pod})
    }

    /// REQ: OPS-014, CLU-010 — native replicas first (by site), the primary last; pods,
    /// nodes already on the version, newer ones, and local builds are left alone; nodes that are
    /// down are listed apart; `--node` keeps the ones named.
    #[test]
    fn ops_014_upgrade_order() {
        let view = json!({"enabled": true, "nodes": [
            node("c0", "k3s", "replica", "0.7.0", true, Some("telltale-0")),
            node("p1", "proxmox", "primary", "0.7.0", true, None),
            node("z9", "pi", "replica", "0.7.0", true, None),
            node("a1", "attic", "replica", "0.8.0", true, None),
            node("n2", "new", "replica", "0.9.0", true, None),
            node("d3", "dev", "replica", "dev", true, None),
            node("x4", "gone", "replica", "0.7.0", false, None),
        ]});
        let p = upgrade_plan(&view, "0.8.0", &[]);
        let order: Vec<(&str, bool)> = p.steps.iter().map(|s| (s.id.as_str(), s.primary)).collect();
        assert_eq!(order, vec![("z9", false), ("p1", true)]);
        assert_eq!(p.steps[0].label, "pi (z9)");
        assert_eq!(p.down, vec!["gone (x4)".to_owned()]);
        let why: Vec<&str> = p.skipped.iter().map(|(_, r)| r.as_str()).collect();
        assert_eq!(
            why,
            vec![
                "a Kubernetes pod: the chart upgrades it",
                "already on 0.8.0",
                "runs 0.9.0, newer than 0.8.0",
                "a local build (dev)",
            ]
        );
        let only = upgrade_plan(&view, "0.8.0", &["proxmox".into()]);
        assert_eq!(only.steps.len(), 1);
        assert!(only.down.is_empty() && only.skipped.is_empty());
        // An edge build sorts before its release.
        let p = upgrade_plan(&view, "0.8.0-edge.5", &[]);
        assert!(
            p.skipped
                .iter()
                .any(|(n, r)| n == "attic (a1)" && r.contains("newer"))
        );
        // REQ: OPS-014 (ADR-182) — a witness only votes (it would answer "a witness only votes"
        // and stop the run): left alone, to upgrade by hand. A member of the registry never heard
        // from (no version) is down, not "a local build".
        let mut witness = node("w5", "attic-witness", "replica", "0.7.0", true, None);
        witness["witness"] = json!(true);
        let mut unheard = node("u6", "shed", "replica", "", false, None);
        unheard["ready"] = json!(false);
        let view = json!({"enabled": true, "nodes": [
            node("p1", "proxmox", "primary", "0.7.0", true, None), witness, unheard,
        ]});
        let p = upgrade_plan(&view, "0.8.0", &[]);
        assert_eq!(p.steps.len(), 1, "{p:?}");
        assert_eq!(
            p.skipped,
            vec![(
                "attic-witness (w5)".to_owned(),
                "a witness: upgrade it by hand (telltale self-update)".to_owned()
            )]
        );
        assert_eq!(p.down, vec!["shed (u6)".to_owned()]);
    }

    /// REQ: OPS-014 (ADR-182) — what the pre-flight read says of a node: ready; a container left
    /// alone; its update service off, a request waiting, a run under way (not one older than the
    /// node's own lock), or a stable node asked for an edge build: the run stops first.
    #[test]
    fn ops_014_the_preflight_reads_each_node() {
        let now = 1_795_000_000_000;
        let at = |ms: u64| telltale_api::time::format_us(ms * 1000);
        let ok = json!({"node": "pi", "version": "0.7.0", "install": "native", "enabled": true});
        assert_eq!(preflight(&ok, "0.8.0", now), Preflight::Ready);
        let with = |k: &str, v: Value| {
            let mut u = ok.clone();
            u[k] = v;
            u
        };
        assert!(matches!(
            preflight(&with("install", json!("container")), "0.8.0", now),
            Preflight::Leave(_)
        ));
        for (u, why) in [
            (with("enabled", json!(false)), "update service is off"),
            (with("pending", json!({"to": "0.8.0"})), "already waiting"),
            (
                with(
                    "last",
                    json!({"state": "installing", "to": "0.8.0", "at": at(now - 60_000)}),
                ),
                "is running on it",
            ),
            // REQ: OPS-014 (ADR-182) — the node holds the version back (its build was installed
            // there and didn't come up, within the day): the run stops before any node is asked,
            // with the node's own words and time.
            (
                with(
                    "held",
                    json!({"to": "0.8.0", "until": "2026-11-21T10:00:00Z",
                           "why": "0.8.0 was installed here and didn't come up: run 1a-2b ended rolled_back"}),
                ),
                "holds 0.8.0 back until 2026-11-21T10:00:00Z: 0.8.0 was installed here",
            ),
        ] {
            match preflight(&u, "0.8.0", now) {
                Preflight::Block(w) => assert!(w.contains(why), "{w}"),
                other => panic!("{u}: {other:?}"),
            }
        }
        assert!(matches!(
            preflight(&ok, "0.8.0-edge.3", now),
            Preflight::Block(w) if w.contains("stable channel")
        ));
        // A run that says `installing` for longer than the node's lock is over (it died).
        let stale = with(
            "last",
            json!({"state": "installing", "to": "0.8.0", "at": at(now - INSTALLING_MS - 1)}),
        );
        assert_eq!(preflight(&stale, "0.8.0", now), Preflight::Ready);
        // A last run that failed (in the downloads, say) or was rolled back doesn't stop the run
        // by itself: only what the node says it holds back does, and only for that version.
        for last in [
            json!({"state": "failed", "to": "0.8.0", "at": at(now - 60_000)}),
            json!({"state": "rolled_back", "to": "0.8.0", "at": at(now - 60_000)}),
        ] {
            assert_eq!(
                preflight(&with("last", last.clone()), "0.8.0", now),
                Preflight::Ready,
                "{last}"
            );
        }
        let other = with("held", json!({"to": "0.8.1", "until": "x", "why": "y"}));
        assert_eq!(preflight(&other, "0.8.0", now), Preflight::Ready);
    }

    /// A fake API: `versions` per node; a POST "installs" by moving the node to the version
    /// and its update service then says `updated` (or fails it when the node is in `fail`). A
    /// node in `disabled` has its update service off; one in `down` is down in the cluster view.
    /// A node in `rolled_back` shows the new version, up and ready, at once (the view before the
    /// health gate is done), says `installing` at the first read and `rolled_back` after it.
    /// `calls` has every request to a node's update route, in order.
    #[derive(Default)]
    struct FakeCluster {
        versions: std::sync::Mutex<Vec<(String, String)>>,
        asked: std::sync::Mutex<Vec<String>>,
        calls: std::sync::Mutex<Vec<String>>,
        fail: Vec<String>,
        disabled: Vec<String>,
        unavailable: Vec<String>,
        rolled_back: Vec<String>,
        down: Vec<String>,
    }

    #[allow(clippy::too_many_lines)] // one fake API: its three routes and their answers
    async fn fake_api(f: Arc<FakeCluster>) -> String {
        use axum::extract::{Path as P, State};
        use axum::routing::get;
        let reply = |v: Value| {
            (
                http::StatusCode::OK,
                [(http::header::CONTENT_TYPE, "application/json")],
                v.to_string(),
            )
        };
        let cluster = move |State(f): State<Arc<FakeCluster>>| async move {
            let nodes: Vec<Value> = f
                .versions
                .lock()
                .unwrap()
                .iter()
                .map(|(id, v)| {
                    let pod = (id == "c0").then_some("telltale-0");
                    node(
                        id,
                        id,
                        if id == "c0" { "primary" } else { "replica" },
                        v,
                        !f.down.contains(id),
                        pod,
                    )
                })
                .collect();
            reply(json!({"enabled": true, "nodes": nodes}))
        };
        let status = move |State(f): State<Arc<FakeCluster>>, P(id): P<String>| async move {
            f.calls.lock().unwrap().push(format!("GET {id}"));
            let asked = f.asked.lock().unwrap().contains(&id);
            // Reads of this node since it was asked (this one included).
            let reads = {
                let calls = f.calls.lock().unwrap();
                let (post, get) = (format!("POST {id}"), format!("GET {id}"));
                calls
                    .iter()
                    .rposition(|c| *c == post)
                    .map_or(0, |i| calls[i..].iter().filter(|c| **c == get).count())
            };
            let last = if f.fail.contains(&id) && asked {
                json!({"id": "r-1", "state": "failed", "error": "checksum mismatch"})
            } else if f.unavailable.contains(&id) && asked {
                json!({"id": "r-1", "state": "unavailable",
                       "error": "the edge channel now serves 0.8.0-edge.9 (commit abc1234), not 0.8.0-edge.5"})
            } else if f.rolled_back.contains(&id) && asked {
                if reads <= 1 {
                    json!({"id": "r-1", "state": "installing"})
                } else {
                    json!({"id": "r-1", "state": "rolled_back",
                           "error": "0.8.0 wasn't healthy after the restart (status 503); 0.7.0 is back and running"})
                }
            } else if asked {
                json!({"id": "r-1", "state": "updated"})
            } else {
                Value::Null
            };
            let version = f
                .versions
                .lock()
                .unwrap()
                .iter()
                .find(|(n, _)| *n == id)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            reply(json!({"node": id, "version": version, "install": "native",
                         "enabled": !f.disabled.contains(&id), "last": last}))
        };
        let post = move |State(f): State<Arc<FakeCluster>>,
                         P(id): P<String>,
                         headers: http::HeaderMap,
                         body: String| async move {
            f.calls.lock().unwrap().push(format!("POST {id}"));
            // REQ: OPS-014, AGT-003 — as the API answers an agent token's change that doesn't
            // say why (the chart's hook holds one): 400, nothing asked.
            if headers
                .get("x-telltale-reason")
                .is_none_or(|r| r.as_bytes().trim_ascii().is_empty())
            {
                return (
                    http::StatusCode::BAD_REQUEST,
                    [(http::header::CONTENT_TYPE, "application/problem+json")],
                    json!({"code": "invalid", "detail": "agents must say why they change something"})
                        .to_string(),
                );
            }
            let to = serde_json::from_str::<Value>(&body).unwrap()["to"]
                .as_str()
                .unwrap()
                .to_owned();
            f.asked.lock().unwrap().push(id.clone());
            if !f.fail.contains(&id) && !f.unavailable.contains(&id) {
                for (n, v) in f.versions.lock().unwrap().iter_mut() {
                    if *n == id {
                        v.clone_from(&to);
                    }
                }
            }
            reply(json!({"node": id, "state": "requested", "pending": {"id": "r-1", "to": to}}))
        };
        let app = axum::Router::new()
            .route("/api/v1/cluster", get(cluster))
            .route("/api/v1/nodes/{id}/update", get(status).post(post))
            .with_state(f);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}")
    }

    fn args(to: &str) -> UpgradeArgs {
        UpgradeArgs {
            to: Some(to.into()),
            to_self: false,
            nodes: Vec::new(),
            timeout: 30,
            skip_down: false,
            skip_unavailable: false,
            skip_if_unreachable: false,
            dry_run: false,
            reason: None,
        }
    }

    fn fake(nodes: &[&str], fail: &[&str]) -> Arc<FakeCluster> {
        Arc::new(FakeCluster {
            versions: std::sync::Mutex::new(
                nodes
                    .iter()
                    .map(|n| ((*n).to_owned(), "0.7.0".to_owned()))
                    .collect(),
            ),
            asked: std::sync::Mutex::default(),
            calls: std::sync::Mutex::default(),
            fail: fail.iter().map(|n| (*n).to_owned()).collect(),
            ..FakeCluster::default()
        })
    }

    /// REQ: OPS-014, AGT-003 (ADR-182) — `ctl upgrade` with an agent token (as the chart's hook
    /// runs it: `analytics:read` and `cluster:upgrade`) against the real API router: its reads
    /// pass (the cluster, the node's info and update state: here the node has no update service,
    /// so the pre-flight stops the run), a dry run works, and its request says why, so it isn't
    /// refused as an agent's change without a reason (400). The audit keeps the reason.
    #[tokio::test]
    async fn ops_014_ctl_upgrade_works_with_an_agent_token() {
        use telltale_api::auth::{self, Auth, Role};
        let dir = tempfile::tempdir().unwrap();
        let mut sources = crate::http::tests::sources_in(dir.path());
        let mut file = telltale_config::Config::default();
        file.node.data_dir =
            telltale_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
        sources.file_config = arc_swap::ArcSwap::from_pointee(file.clone());
        sources.config = arc_swap::ArcSwap::from_pointee(file);
        let state =
            Arc::new(telltale_store::state::State::open(&dir.path().join("state.db")).unwrap());
        let auth = Arc::new(Auth::new(state, auth::Settings::default()));
        let src = Arc::new(sources);
        let _ = src.auth.set(Arc::clone(&auth));
        let now = crate::maintenance::now_ms() / 1000;
        let root = auth
            .create_user("root", "correct horse battery", Role::Admin, false, now)
            .unwrap();
        let (id, secret) = (auth::crypto::random_id(), auth::crypto::random_secret());
        auth.state()
            .create_token(
                &id,
                root.id,
                "hook",
                &auth::crypto::secret_hash(&secret),
                "admin",
                None,
                now,
            )
            .unwrap();
        auth.state()
            .set_token_agent(&id, "analytics:read cluster:upgrade", None, None)
            .unwrap();
        let token = format!("tt_{id}_{secret}");
        let app = telltale_api::router(
            Arc::new(crate::api_backend::ApiBackend {
                src: Arc::clone(&src),
            }),
            Arc::clone(&auth),
        );
        let addr = crate::http::serve("127.0.0.1:0".parse().unwrap(), app, std::future::pending())
            .await
            .unwrap();
        let base = format!("http://{addr}");
        // The reads: the run gets to the pre-flight, which finds the update service off.
        let e = run(
            &base,
            None,
            &token,
            CtlCommand::Upgrade(args("0.8.1")),
            false,
        )
        .await
        .unwrap_err();
        assert!(
            e.contains("nothing was asked") && e.contains("update service is off"),
            "{e}"
        );
        let mut dry = args("0.8.1");
        dry.dry_run = true;
        let out = run(&base, None, &token, CtlCommand::Upgrade(dry), false)
            .await
            .unwrap();
        assert!(out.contains("update service is off"), "{out}");
        // The request: with the reason the upgrade sends, the node answers (a local build here:
        // `update_unsupported`); without one, the API refuses the agent's change.
        let api = Api {
            client: client(None).unwrap(),
            base: base.clone(),
            token: token.clone(),
            reason: None,
        };
        let body = json!({"to": "0.8.1"});
        let (status, p) = api
            .call_raw(http::Method::POST, "nodes/local/update", Some(&body))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{p}");
        assert!(s(&p, "detail").contains("say why"), "{p}");
        let api = api.with_reason("telltale ctl upgrade --to 0.8.1".into());
        let (status, p) = api
            .call_raw(http::Method::POST, "nodes/local/update", Some(&body))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            (status, s(&p, "code").as_str()),
            (http::StatusCode::CONFLICT, "update_unsupported"),
            "{p}"
        );
        let audit = auth.state().audit_page(None, 100, None, None).unwrap();
        assert!(
            audit.iter().any(|e| e.action == "node.update.refused"
                && e.reason.as_deref() == Some("telltale ctl upgrade --to 0.8.1")),
            "{audit:?}"
        );
    }

    /// REQ: OPS-014 (ADR-182) — `--skip-if-unreachable` skips only a first install: a name that
    /// doesn't exist, or every address refusing the connection. A lookup that failed another way,
    /// a timeout, or an address that answers (the failure was TLS or HTTP) is no first install.
    #[test]
    fn ops_014_only_a_first_install_is_skipped() {
        use std::io::ErrorKind::{ConnectionRefused, TimedOut};
        assert!(first_install(true, &[]).is_some());
        assert!(first_install(false, &[Err(ConnectionRefused)]).is_some());
        assert!(first_install(false, &[Err(ConnectionRefused), Err(ConnectionRefused)]).is_some());
        assert!(
            first_install(false, &[]).is_none(),
            "a lookup that failed otherwise"
        );
        assert!(
            first_install(false, &[Err(TimedOut)]).is_none(),
            "a timeout or a drop"
        );
        assert!(first_install(false, &[Err(ConnectionRefused), Err(TimedOut)]).is_none());
        assert!(
            first_install(false, &[Ok(())]).is_none(),
            "it answers: TLS or HTTP failed"
        );
        for (m, nx) in [
            (
                "failed to lookup address information: Name or service not known",
                true,
            ),
            (
                "failed to lookup address information: Name does not resolve",
                true,
            ),
            (
                "failed to lookup address information: Temporary failure in name resolution",
                false,
            ),
            ("failed to lookup address information: Try again", false),
        ] {
            assert_eq!(no_such_name(&std::io::Error::other(m)), nx, "{m}");
        }
    }

    /// REQ: OPS-014 (ADR-182) — a node is done only once its update service has recorded
    /// `updated` for this request, not as soon as the cluster view shows it on the version and
    /// ready: the health gate runs after that, and a rollback inside it stops the run before the
    /// next node is asked.
    #[tokio::test]
    async fn ops_014_ctl_waits_for_updated_and_stops_at_a_late_rollback() {
        let f = Arc::new(FakeCluster {
            rolled_back: vec!["dns-01".into()],
            ..Arc::into_inner(fake(&["c0", "dns-01", "dns-02"], &[])).unwrap()
        });
        let base = fake_api(Arc::clone(&f)).await;
        let e = run(&base, None, "t", CtlCommand::Upgrade(args("0.8.0")), false)
            .await
            .unwrap_err();
        assert!(
            e.contains("dns-01") && e.contains("rolled_back") && e.contains("status 503"),
            "{e}"
        );
        assert_eq!(
            *f.asked.lock().unwrap(),
            vec!["dns-01"],
            "dns-02 is never asked"
        );
    }

    /// REQ: OPS-014 (ADR-182) — a node behind a pinned edge build that can't be fetched any more
    /// (main has published a newer one): without --skip-unavailable the run stops there and the
    /// nodes after it aren't asked (the hook fails, the sync stays blocked); with it the node is
    /// left on its version, said loudly, and the run goes on.
    #[tokio::test]
    async fn ops_014_ctl_upgrade_and_an_edge_build_no_longer_served() {
        let edge = |skip: bool| {
            let mut a = args("0.8.0-edge.5");
            a.skip_unavailable = skip;
            a
        };
        let unserved = || {
            let mut f = Arc::into_inner(fake(&["c0", "dns-01", "dns-02"], &[])).unwrap();
            for (_, v) in f.versions.get_mut().unwrap().iter_mut() {
                *v = "0.8.0-edge.1".into();
            }
            f.unavailable = vec!["dns-01".into()];
            Arc::new(f)
        };
        let f = unserved();
        let base = fake_api(Arc::clone(&f)).await;
        let e = run(&base, None, "t", CtlCommand::Upgrade(edge(false)), false)
            .await
            .unwrap_err();
        assert!(
            e.contains("dns-01") && e.contains("can't be fetched any more") && e.contains("skip"),
            "{e}"
        );
        assert_eq!(
            *f.asked.lock().unwrap(),
            vec!["dns-01"],
            "dns-02 isn't asked"
        );
        let f = unserved();
        let base = fake_api(Arc::clone(&f)).await;
        let out = run(&base, None, "t", CtlCommand::Upgrade(edge(true)), false)
            .await
            .unwrap();
        assert_eq!(*f.asked.lock().unwrap(), vec!["dns-01", "dns-02"]);
        assert!(
            out.contains("can't be fetched any more (--skip-unavailable)")
                && out.contains("Upgraded to 0.8.0-edge.5:"),
            "{out}"
        );
    }

    /// REQ: OPS-014 (ADR-182) — with every native node already on the version (a sync after the
    /// bump, or any later one) no request is sent at all: no node is read for its update state,
    /// none is asked, nothing is downloaded.
    #[tokio::test]
    async fn ops_014_nodes_on_the_version_are_not_asked() {
        let f = fake(&["c0", "dns-01", "dns-02"], &[]);
        for (_, v) in f.versions.lock().unwrap().iter_mut() {
            *v = "0.8.0".into();
        }
        let base = fake_api(Arc::clone(&f)).await;
        let out = run(&base, None, "t", CtlCommand::Upgrade(args("0.8.0")), false)
            .await
            .unwrap();
        assert!(
            f.calls.lock().unwrap().is_empty(),
            "{:?}",
            f.calls.lock().unwrap()
        );
        assert!(out.contains("No node needed 0.8.0."), "{out}");
    }

    /// REQ: OPS-014 (ADR-182) — pre-flight: every planned node is read before any is asked, and
    /// one that can't take the request (here its update service is off) stops the run with
    /// nothing asked, the error naming it, with `--skip-down` too: that skips only nodes that
    /// are down, and a node set up wrong isn't one. A node that is down is left out with it.
    #[tokio::test]
    async fn ops_014_a_node_that_cant_take_the_upgrade_stops_the_run_before_any_is_asked() {
        let f = Arc::new(FakeCluster {
            disabled: vec!["dns-02".into()],
            ..Arc::into_inner(fake(&["c0", "dns-01", "dns-02"], &[])).unwrap()
        });
        let base = fake_api(Arc::clone(&f)).await;
        let e = run(&base, None, "t", CtlCommand::Upgrade(args("0.8.0")), false)
            .await
            .unwrap_err();
        assert!(
            e.contains("nothing was asked") && e.contains("dns-02") && e.contains("off"),
            "{e}"
        );
        assert!(f.asked.lock().unwrap().is_empty(), "no node was asked");
        assert_eq!(
            *f.calls.lock().unwrap(),
            vec!["GET dns-01", "GET dns-02"],
            "only the pre-flight reads"
        );
        // --skip-down doesn't skip it: its update service is off, it isn't down.
        let skip_down = || {
            let mut a = args("0.8.0");
            a.skip_down = true;
            a
        };
        let e = run(&base, None, "t", CtlCommand::Upgrade(skip_down()), false)
            .await
            .unwrap_err();
        assert!(
            e.contains("nothing was asked") && e.contains("dns-02") && e.contains("off"),
            "{e}"
        );
        assert!(f.asked.lock().unwrap().is_empty(), "no node was asked");
        // A node that is down: --skip-down leaves it out, and dns-01 is upgraded.
        let f = Arc::new(FakeCluster {
            down: vec!["dns-02".into()],
            ..Arc::into_inner(fake(&["c0", "dns-01", "dns-02"], &[])).unwrap()
        });
        let base = fake_api(Arc::clone(&f)).await;
        let out = run(&base, None, "t", CtlCommand::Upgrade(skip_down()), false)
            .await
            .unwrap();
        assert_eq!(*f.asked.lock().unwrap(), vec!["dns-01"]);
        assert!(out.contains("dns-02 (dns-02): down (--skip-down)"), "{out}");
    }

    /// REQ: OPS-014 — `ctl upgrade` asks one node at a time, waits for each to be back on the
    /// version, never asks the pod, and stops at the first failure with the node's error.
    #[tokio::test]
    async fn ops_014_ctl_upgrade_goes_one_node_at_a_time_and_stops_on_failure() {
        let f = fake(&["c0", "dns-01", "dns-02"], &[]);
        let base = fake_api(Arc::clone(&f)).await;
        let out = run(&base, None, "t", CtlCommand::Upgrade(args("0.8.0")), false)
            .await
            .unwrap();
        assert_eq!(*f.asked.lock().unwrap(), vec!["dns-01", "dns-02"]);
        assert!(out.contains("Upgraded to 0.8.0:"), "{out}");
        assert!(
            out.contains("left alone: telltale-0: a Kubernetes pod"),
            "{out}"
        );

        let f = fake(&["c0", "dns-01", "dns-02"], &["dns-01"]);
        let base = fake_api(Arc::clone(&f)).await;
        let e = run(&base, None, "t", CtlCommand::Upgrade(args("0.8.0")), false)
            .await
            .unwrap_err();
        assert!(
            e.contains("dns-01") && e.contains("checksum mismatch"),
            "{e}"
        );
        assert_eq!(
            *f.asked.lock().unwrap(),
            vec!["dns-01"],
            "dns-02 is never asked"
        );

        // Nothing listening: an error, or "nothing to upgrade yet" for the chart's first install.
        let mut a = args("0.8.0");
        let e = run(
            "http://127.0.0.1:9",
            None,
            "t",
            CtlCommand::Upgrade(args("0.8.0")),
            false,
        )
        .await;
        assert!(e.is_err());
        a.skip_if_unreachable = true;
        let out = run(
            "http://127.0.0.1:9",
            None,
            "t",
            CtlCommand::Upgrade(a),
            false,
        )
        .await
        .unwrap();
        assert!(out.contains("Nothing to upgrade to 0.8.0"), "{out}");
    }
}
