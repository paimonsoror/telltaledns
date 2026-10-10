//! `telltale ctl` (REQ: API-008; T7.25): the REST API from a shell. Friendly commands for the
//! common jobs (status, the query log, top lists, block/allow, pause, flush, the running
//! configuration, agent plans) and `get`/`post`/`put`/`delete` for everything else, with an
//! API token (`TELLTALE_TOKEN` or `--token-file`) against a running node. `--json` prints the
//! API's own JSON, for scripts.

use std::fmt::Write as _;
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
    /// Flush the cache (everything, or one name).
    Flush {
        #[arg(long)]
        name: Option<String>,
        /// Also every name under `--name`.
        #[arg(long)]
        subtree: bool,
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
    /// Only these devices: names, IPs, or CIDRs (repeatable).
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
}

impl Api {
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
        let url = self.url(path);
        let mut req = http::Request::builder()
            .method(method)
            .uri(url.as_str())
            .header("authorization", format!("Bearer {}", self.token))
            .header("accept", "application/json");
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
        if status.is_success() {
            Ok(v)
        } else {
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

/// Runs `cmd` against `base` with `token`; returns the text to print.
#[allow(clippy::too_many_lines)] // one arm per command
pub(crate) async fn run(
    base: &str,
    token: &str,
    cmd: CtlCommand,
    json_out: bool,
) -> Result<String, String> {
    let api = Api {
        client: telltale_filter::fetch::Client::new(
            Arc::new(telltale_filter::fetch::SystemResolver),
            &[],
        )?,
        base: base.to_owned(),
        token: token.to_owned(),
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
}
