//! TelltaleDNS binary: CLI, role wiring, and signal handling (`spec/02-architecture.md` §1).

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

mod anomaly;
mod api_backend;
mod archive;
mod auth_setup;
mod backup;
mod build_info;
mod cache_history;
mod cluster;
mod datadir;
mod explain;
mod federated;
mod forward;
mod gitsource;
mod host;
mod http;
mod import;
mod lists;
mod managed;
mod masking;
mod mcp_stdio;
mod pihole;
mod pipeline;
mod qlog_cli;
mod replication;
mod rollups;
mod selfupdate;
mod server;
mod ship;
mod tail;
mod technitium;
mod updates;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use telltale_config::Loader;
use telltale_policy::LocalData;
use tracing::{error, info, warn};

// REQ: OPS-001, 02 §3 — mimalloc everywhere. The static musl image would otherwise use musl's
// allocator, which roughly halved cache-hit throughput in the bench harness.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Default config file location (`spec/08` §3.4).
const DEFAULT_CONFIG: &str = "/etc/telltale/telltale.toml";

/// TelltaleDNS — see every question, answer on your terms.
#[derive(Debug, Parser)]
#[command(name = "telltale", version = build_info::LINE, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the resolver.
    Run {
        /// Config files, later ones overriding earlier ones. Defaults to `$TELLTALE_CONFIG`,
        /// then `/etc/telltale/telltale.toml` if it exists, else built-in defaults.
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
    },
    /// Inspect and validate configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Built-in upstream presets (Cloudflare, Quad9, AdGuard, ...).
    Presets {
        #[command(subcommand)]
        command: PresetsCommand,
    },
    /// Filter lists (blocklists and allowlists).
    Lists {
        #[command(subcommand)]
        command: ListsCommand,
    },
    /// The audit log of changes (users, tokens, sign-ins, reloads): list and verify.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Sign-in administration: the first-run setup token, password hashes.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Search the query log (newest first), offline from the data directory.
    // REQ: OBS-003
    Qlog {
        #[command(subcommand)]
        command: QlogCommand,
    },
    /// Explain how a query would be handled for a client: who the client is, its groups,
    /// every matching rule with its list line, the decision, and the upstream route.
    /// Reads the config and data directory; the server doesn't need to be running.
    // REQ: FLT-013
    Explain {
        /// The name to look up, e.g. ads.example.com.
        name: String,
        /// The client's IP address.
        #[arg(long, default_value = "127.0.0.1")]
        client: std::net::IpAddr,
        /// Query type.
        #[arg(short = 't', long, default_value = "A")]
        qtype: String,
        /// The client's MAC address (default: from the neighbor table).
        #[arg(long)]
        mac: Option<String>,
        /// A DoH/DoT client ID.
        #[arg(long = "client-id")]
        client_id: Option<String>,
        /// Print JSON (the API's response format) instead of text.
        #[arg(long)]
        json: bool,
        /// Config files (same defaults as `telltale run`).
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
    },
    /// Import configuration from other DNS servers.
    // REQ: API-007
    Import {
        #[command(subcommand)]
        command: ImportCommand,
    },
    /// Serve MCP to an AI agent over stdin/stdout (the `stdio` transport), relaying to a
    /// running node's `/mcp` with an API token (`TELLTALE_TOKEN`, or `--token-file`).
    /// Agents that speak HTTP can use `http://<node>:8053/mcp` directly.
    // REQ: AGT-006
    Mcp {
        /// Use the stdio transport (the only one this command offers).
        #[arg(long)]
        stdio: bool,
        /// The node's API address (default: from the config files' `[api] listen`).
        #[arg(long)]
        url: Option<String>,
        /// Read the API token from this file instead of `TELLTALE_TOKEN`.
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Config files (same defaults as `telltale run`), to find the API address.
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
    },
    /// Back up this node's configuration and data to one file, or restore one.
    // REQ: API-007
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Clusters: create one, issue join tokens, join one, show this node's membership.
    // REQ: CLU-001
    Cluster {
        #[command(subcommand)]
        command: ClusterCommand,
        /// Config files (same defaults as `telltale run`).
        #[arg(short, long = "config", global = true)]
        config: Vec<PathBuf>,
    },
    /// Exit 0 if the server answers 200 at `url` (a container healthcheck without a shell).
    // REQ: OPS-004, OPS-006
    Health {
        #[arg(long, default_value = "http://127.0.0.1:8053/readyz")]
        url: String,
    },
    /// Update this binary to the latest release (native installs; containers pull a new
    /// image). Verifies the release signature and checksum before replacing anything.
    // REQ: OPS-004
    SelfUpdate {
        /// Which releases to follow.
        #[arg(long, value_enum, default_value = "stable")]
        channel: selfupdate::Channel,
        /// Only report whether an update is available.
        #[arg(long)]
        check: bool,
        /// Restart the `telltale` systemd service after updating.
        #[arg(long)]
        restart: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ClusterCommand {
    /// Create a cluster with this node as its primary (it generates and keeps the cluster CA).
    /// Run as the user telltale runs as, then restart telltale.
    Init {
        /// Cluster name.
        #[arg(long)]
        name: String,
        /// URLs other nodes reach this node's cluster port at (repeatable), e.g.
        /// `https://192.168.3.2:8443`. Put every address peers might use (LAN IP, DNS name).
        #[arg(long = "advertise", required = true)]
        advertise: Vec<String>,
        /// Site label (default: `[cluster] site`).
        #[arg(long)]
        site: Option<String>,
        /// Where the cluster's configuration comes from (ADR-048): `api` (this node's file and
        /// UI) or `gitops` (only GitOps-managed nodes may publish it).
        #[arg(long = "config-authority", default_value = "api")]
        config_authority: String,
    },
    /// Make this (eligible) node the primary when the primary is gone (ADR-051). The web UI's
    /// Cluster page does the same without a restart.
    Promote {
        /// Coordinate the cluster but keep the last configuration (a cluster configured from Git
        /// whose Git-managed nodes are all down).
        #[arg(long)]
        emergency: bool,
    },
    /// Change where the cluster's configuration comes from: `api` or `gitops` (on the primary).
    SetAuthority { authority: String },
    /// How the cluster fails over (ADR-056): `manual` (promote by hand) or `auto` (elected by
    /// vote; needs 3 or more voters, e.g. two eligible nodes and a witness). On the primary.
    SetFailover { mode: String },
    /// Run this node as a witness: it only votes in elections (no DNS, no lists, no API).
    Witness,
    /// Rotate the cluster CA (on the primary, while it runs). Every node first trusts the new
    /// CA next to the old, then gets a certificate from it, then the old CA is retired; each
    /// step waits until every member is ready, so no link breaks (ADR-066).
    RotateCa {
        /// Show the rotation's phase and which members it's waiting for.
        #[arg(long)]
        status: bool,
    },
    /// Join tokens (run on the primary).
    Token {
        #[command(subcommand)]
        command: ClusterTokenCommand,
    },
    /// Join the cluster a token belongs to, then restart telltale.
    Join {
        /// The `tt_join_…` token from `telltale cluster token create`.
        token: String,
        /// URLs other nodes reach this node at (optional: replicas dial out).
        #[arg(long = "advertise")]
        advertise: Vec<String>,
        /// Site label (default: `[cluster] site`).
        #[arg(long)]
        site: Option<String>,
        /// May become primary (needs persistent storage).
        #[arg(long)]
        eligible: bool,
        /// Join as a witness: votes in automatic failover only (needs --advertise).
        #[arg(long)]
        witness: bool,
    },
    /// Show this node's cluster identity (offline; live peers are in the API and UI).
    Status,
}

#[derive(Debug, Subcommand)]
enum ClusterTokenCommand {
    /// Print a join token. Reusable until it expires, so one token can sit in a Kubernetes
    /// Secret for every pod.
    Create {
        /// Lifetime: 30m, 1h, 7d, ... (default 1h).
        #[arg(long, default_value = "1h", value_parser = cluster::parse_ttl)]
        ttl: u64,
        /// Cluster URLs to put in the token (default: this node's advertise URLs).
        #[arg(long = "url")]
        urls: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    /// Write a backup: the config files, users and API tokens, devices and names made in the
    /// UI, the audit log, statistics history, and anomaly baselines (the query log with
    /// --include-qlog). Safe while TelltaleDNS runs. The file is owner-only: it holds
    /// password hashes.
    Create {
        /// Also include the query log (can be large).
        #[arg(long)]
        include_qlog: bool,
        /// Where to write it (default: `telltale-<node>-<time>.ttbk` here).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Config files (same defaults as `telltale run`).
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
    },
    /// Restore a backup onto this machine. Stop TelltaleDNS first. Every file is checked
    /// before anything is written; existing files are only replaced with --force.
    Restore {
        /// The `.ttbk` file.
        file: PathBuf,
        /// Data directory (default: the one it was taken from).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Where the config files go (default: where they were).
        #[arg(long)]
        config_dir: Option<PathBuf>,
        /// Replace existing files.
        #[arg(long)]
        force: bool,
    },
    /// Check a backup and list what's in it.
    Show {
        /// The `.ttbk` file.
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ImportCommand {
    /// Convert a zone file (Technitium, BIND, `PowerDNS` export) into `[[record]]` entries.
    /// Prints TOML to add to your config; the header lists what had no local equivalent.
    Zone {
        /// The zone file.
        file: PathBuf,
        /// The zone's name, if the file has no `$ORIGIN` line (e.g. home.arpa).
        #[arg(long)]
        origin: Option<String>,
        /// Write the TOML here instead of to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Convert a Pi-hole setup (v6 Teleporter zip, v5 Teleporter tar.gz, a gravity.db, or a
    /// directory like /etc/pihole) into a TelltaleDNS configuration: upstreams, conditional
    /// forwarding, local DNS and CNAME records, adlists, allow/deny domains, groups, and
    /// clients. The header lists everything that has no equivalent.
    Pihole {
        /// The Teleporter archive, gravity.db, or Pi-hole directory.
        path: PathBuf,
        /// Write the TOML here instead of to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Read a running Technitium DNS Server through its API (forwarders, zones and records,
    /// forwarder zones, block lists, allowed/blocked names, Advanced Blocking groups, DHCP
    /// reservations) and print a TelltaleDNS configuration. Create an API token in
    /// Technitium (Administration → Sessions → Create Token) and pass it in the
    /// `TECHNITIUM_TOKEN` environment variable or a file.
    Technitium {
        /// The web console's address, e.g. `http://192.168.1.2:5380`.
        url: String,
        /// Read the API token from this file instead of `TECHNITIUM_TOKEN`.
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Write the TOML here instead of to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Print the first-run setup token (until the first admin exists). The server creates it
    /// at startup and keeps it in `<data_dir>/setup-token`.
    // REQ: API-003
    SetupToken {
        /// Config files (same defaults as `telltale run`).
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
    },
    /// Read a password from stdin and print its Argon2id hash, for
    /// `TELLTALE_BOOTSTRAP_ADMIN_PASSWORD_HASH`.
    HashPassword,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Check the audit log's hash chain; exits non-zero if an entry was changed or removed.
    // REQ: API-006
    Verify {
        /// Config files (same defaults as `telltale run`).
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
    },
    /// Print audit entries, newest first.
    List {
        /// Config files (same defaults as `telltale run`).
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
        /// How many.
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: usize,
        /// Only this action or prefix (`user.`, `config.reload`).
        #[arg(long)]
        action: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ListsCommand {
    /// Download every enabled list now and store it in `<data_dir>/lists`, as the running
    /// server would. Exits non-zero if any list failed.
    // REQ: FLT-004
    Fetch {
        /// Config files (same defaults as `telltale run`).
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
    },
    /// Compile the stored lists into a new filter snapshot now and print the result
    /// (the server does this automatically when lists change).
    // REQ: FLT-003
    Compile {
        /// Config files (same defaults as `telltale run`).
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
        /// Compile threads (default: `[filter] compile_threads`).
        #[arg(long)]
        threads: Option<usize>,
    },
    /// Parse the stored lists and report rules, unsupported and invalid lines (with the
    /// first problem lines of each list). Exits non-zero if a list has invalid lines.
    // REQ: FLT-001
    Check {
        /// Config files (same defaults as `telltale run`).
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
        /// Only these lists.
        #[arg(long = "list")]
        lists: Vec<String>,
        /// Print every rule in canonical form.
        #[arg(long)]
        rules: bool,
    },
}

#[derive(Debug, Subcommand)]
enum QlogCommand {
    /// Find logged queries. Filters combine (AND); prints newest first.
    Search {
        /// Name to look for (a substring unless --match says otherwise).
        name: Option<String>,
        /// How to match the name: substring, exact, suffix (name or subdomain), glob, regex.
        #[arg(long = "match", default_value = "substring")]
        mode: String,
        /// Client IP address.
        #[arg(long)]
        client: Option<std::net::IpAddr>,
        /// Status: cached, forwarded, stale, local, special, blocked, refused, ... (repeatable).
        #[arg(long)]
        status: Vec<String>,
        /// Query type, e.g. AAAA (repeatable).
        #[arg(short = 't', long)]
        qtype: Vec<String>,
        /// Only the last N seconds.
        #[arg(long)]
        since: Option<u64>,
        /// Only queries that took at least this many milliseconds.
        #[arg(long = "min-ms")]
        min_ms: Option<u32>,
        /// Rows per page.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Continue after a previous page (printed at the end of each page).
        #[arg(long)]
        cursor: Option<String>,
        /// JSON lines instead of text.
        #[arg(long)]
        json: bool,
        /// Config files (same defaults as `telltale run`).
        #[arg(short, long = "config")]
        config: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PresetsCommand {
    /// List the catalog.
    List,
    /// Print a preset as `[[upstream]]` entries plus a group, ready to paste into telltale.toml.
    // REQ: UPS-004
    Show {
        /// Preset ID (see `telltale presets list`).
        id: String,
        /// Only these protocols (comma-separated): udp, tcp, tls, https.
        #[arg(long, value_delimiter = ',')]
        proto: Vec<String>,
        /// Template values, e.g. `--param profile=abc123` for NextDNS.
        #[arg(long = "param", value_name = "KEY=VALUE")]
        params: Vec<String>,
        /// Leave out IPv6 addresses.
        #[arg(long)]
        no_ipv6: bool,
        /// Group name (default: the preset ID; use "default" to make it the main group).
        #[arg(long)]
        group: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Validate config files offline. Later files override earlier ones; TELLTALE_* env vars
    /// override files unless --no-env is given.
    // REQ: OPS-005
    Check {
        /// Config files (e.g. telltale.toml node.toml).
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Ignore TELLTALE_* environment variables.
        #[arg(long)]
        no_env: bool,
        /// Print the effective config (defaults + files + env) as TOML.
        #[arg(long)]
        print: bool,
    },
    /// Print the JSON Schema for telltale.toml (for editor completion).
    Schema,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run { config } => run(config),
        Command::Config { command } => run_config(command),
        Command::Presets { command } => run_presets(command),
        Command::Lists { command } => run_lists(command),
        Command::Qlog {
            command:
                QlogCommand::Search {
                    name,
                    mode,
                    client,
                    status,
                    qtype,
                    since,
                    min_ms,
                    limit,
                    cursor,
                    json,
                    config,
                },
        } => {
            let args = qlog_cli::Args {
                name,
                mode,
                client,
                status,
                qtype,
                since_secs: since,
                min_ms,
                limit,
                cursor,
                json,
            };
            Ok(
                server::load(&config_files(config)).map_or(ExitCode::FAILURE, |cfg| {
                    match qlog_cli::run(&cfg, &args, &mut io::stdout().lock()) {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(e) => {
                            eprintln!("error: {e}");
                            ExitCode::FAILURE
                        }
                    }
                }),
            )
        }
        Command::Auth { command } => Ok(run_auth(command)),
        Command::Audit { command } => Ok(run_audit(command)),
        Command::Explain {
            name,
            client,
            qtype,
            mac,
            client_id,
            json,
            config,
        } => Ok(run_explain(
            &name,
            client,
            &qtype,
            mac.as_deref(),
            client_id.as_deref(),
            json,
            config,
        )),
        Command::SelfUpdate {
            channel,
            check,
            restart,
        } => Ok(run_self_update(channel, check, restart)),
        Command::Import { command } => Ok(run_import(command)),
        Command::Backup { command } => Ok(run_backup(command)),
        Command::Mcp {
            stdio,
            url,
            token_file,
            config,
        } => Ok(run_mcp(stdio, url, token_file.as_deref(), config)),
        Command::Cluster { command, config } => Ok(run_cluster(command, config)),
        Command::Health { url } => Ok(match health(&url) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("unhealthy: {e}");
                ExitCode::FAILURE
            }
        }),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("telltale: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_cluster(command: ClusterCommand, config: Vec<PathBuf>) -> ExitCode {
    let Some(cfg) = server::load(&config_files(config)) else {
        return ExitCode::FAILURE;
    };
    match command {
        ClusterCommand::Init {
            name,
            advertise,
            site,
            config_authority,
        } => cluster::init(
            &cfg,
            &mut io::stdout().lock(),
            &name,
            advertise,
            site.as_deref(),
            &config_authority,
        ),
        ClusterCommand::Promote { emergency } => {
            cluster::promote_offline(&cfg, &mut io::stdout().lock(), emergency)
        }
        ClusterCommand::SetAuthority { authority } => {
            cluster::set_authority(&cfg, &mut io::stdout().lock(), &authority)
        }
        ClusterCommand::SetFailover { mode } => {
            cluster::set_failover(&cfg, &mut io::stdout().lock(), &mode)
        }
        ClusterCommand::Witness => cluster::witness(&cfg),
        ClusterCommand::RotateCa { status } => {
            cluster::rotate_ca(&cfg, &mut io::stdout().lock(), status)
        }
        ClusterCommand::Token {
            command: ClusterTokenCommand::Create { ttl, urls },
        } => cluster::token_create(&cfg, &mut io::stdout().lock(), ttl, urls),
        ClusterCommand::Join {
            token,
            advertise,
            site,
            eligible,
            witness,
        } => cluster::join(
            &cfg,
            &mut io::stdout().lock(),
            &token,
            advertise,
            site.as_deref(),
            eligible,
            witness,
        ),
        ClusterCommand::Status => cluster::status(&cfg, &mut io::stdout().lock()),
    }
}

/// The local API's URL from the config files' `[api] listen` (warnings stay off stdout,
/// which is the MCP channel).
fn api_url(config: Vec<PathBuf>) -> Result<String, Vec<telltale_config::ConfigError>> {
    let files = config_files(config);
    let l = files
        .iter()
        .fold(Loader::new(), Loader::file)
        .process_env()
        .load()?;
    let a = l.config.api.listen;
    let host = if a.ip().is_unspecified() {
        "127.0.0.1".to_owned()
    } else if a.is_ipv6() {
        format!("[{}]", a.ip())
    } else {
        a.ip().to_string()
    };
    Ok(format!("http://{host}:{}", a.port()))
}

// REQ: AGT-006 (T6.6, ADR-065)
fn run_mcp(
    stdio: bool,
    url: Option<String>,
    token_file: Option<&Path>,
    config: Vec<PathBuf>,
) -> ExitCode {
    if !stdio {
        eprintln!("error: say --stdio (HTTP agents use http://<node>:8053/mcp directly)");
        return ExitCode::FAILURE;
    }
    let url = match url.map_or_else(|| api_url(config), Ok) {
        Ok(u) => u,
        Err(errs) => {
            for e in &errs {
                eprintln!("error: {e}");
            }
            return ExitCode::FAILURE;
        }
    };
    let token = match token_file {
        Some(p) => std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display())),
        None => std::env::var("TELLTALE_TOKEN").map_err(|_| {
            "set TELLTALE_TOKEN to an API token (an agent token is best), or use --token-file"
                .to_owned()
        }),
    };
    let result = token.and_then(|t| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?
            .block_on(mcp_stdio::run(&url, t.trim()))
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// REQ: API-007 (T6.7, ADR-063)
fn run_backup(command: BackupCommand) -> ExitCode {
    let result = match command {
        BackupCommand::Create {
            include_qlog,
            output,
            config,
        } => {
            let files = config_files(config);
            let Some(cfg) = server::load(&files) else {
                return ExitCode::FAILURE;
            };
            let out = output.unwrap_or_else(|| backup::default_name(cfg.node.name.as_str()));
            backup::create(&files, &cfg, include_qlog, &out).map(|c| {
                eprintln!(
                    "wrote {} ({} files, {} KiB). It holds password hashes: keep it private.",
                    c.path.display(),
                    c.entries,
                    c.bytes.div_ceil(1024)
                );
            })
        }
        BackupCommand::Restore {
            file,
            data_dir,
            config_dir,
            force,
        } => backup::restore(&file, data_dir.as_deref(), config_dir.as_deref(), force).map(|r| {
            eprintln!(
                "restored {} files from {} (node {}, TelltaleDNS {}): data in {}, config in {}",
                r.files,
                file.display(),
                r.manifest.node,
                r.manifest.telltale_version,
                r.data_dir.display(),
                r.config_dir.display()
            );
            if Path::new(&r.manifest.data_dir) != r.data_dir {
                eprintln!(
                    "note: the restored config files say data_dir = {}; set it to {} (or add a file that does).",
                    r.manifest.data_dir,
                    r.data_dir.display()
                );
            }
            if r.manifest.cluster_member {
                eprintln!(
                    "note: the backup came from a cluster member; cluster identity isn't in backups. Start this node, then `telltale cluster init` or join it again (docs: Clusters)."
                );
            }
        }),
        BackupCommand::Show { file } => backup::show(&file).map(|m| {
            let mut out = io::stdout().lock();
            let total: u64 = m.entries.iter().map(|e| e.size).sum();
            let _ = writeln!(
                out,
                "TelltaleDNS {} backup of node `{}`, taken {} (unix), {} files, {} KiB, checksums OK",
                m.telltale_version,
                m.node,
                m.created,
                m.entries.len(),
                total.div_ceil(1024)
            );
            for e in &m.entries {
                let _ = writeln!(out, "  {:>10}  {}", e.size, e.path);
            }
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// REQ: API-007
fn run_import(command: ImportCommand) -> ExitCode {
    match command {
        ImportCommand::Zone {
            file,
            origin,
            output,
        } => run_import_zone(&file, origin.as_deref(), output.as_deref()),
        ImportCommand::Pihole { path, output } => run_import_pihole(&path, output.as_deref()),
        ImportCommand::Technitium {
            url,
            token_file,
            output,
        } => run_import_technitium(&url, token_file.as_deref(), output.as_deref()),
    }
}

// REQ: API-007 (T6.4, ADR-062)
fn run_import_technitium(url: &str, token_file: Option<&Path>, output: Option<&Path>) -> ExitCode {
    let token = match token_file {
        Some(p) => std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display())),
        None => std::env::var("TECHNITIUM_TOKEN").map_err(|_| {
            "set TECHNITIUM_TOKEN to a Technitium API token (or use --token-file)".to_owned()
        }),
    };
    let fetched = token.and_then(|t| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?
            .block_on(technitium::fetch(url, t.trim()))
    });
    match fetched {
        Ok(ex) => {
            let im = technitium::convert(&ex, url);
            write_import(&im, output, &format!("Technitium {}", ex.version))
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// REQ: API-007 (T6.3, ADR-061)
fn run_import_pihole(path: &Path, output: Option<&Path>) -> ExitCode {
    match pihole::Source::load(path)
        .and_then(|src| pihole::convert(&src, &path.display().to_string()))
    {
        Ok(im) => write_import(&im, output, &format!("Pi-hole {}", im.version)),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Checks an importer's output loads as config, writes it, and prints the summary and notes.
fn write_import(im: &pihole::Imported, output: Option<&Path>, from: &str) -> ExitCode {
    // The result must load as config, with valid record values.
    match Loader::new().toml_str("import", im.toml.clone()).load() {
        Ok(l) => {
            let (_, report) = LocalData::from_config(&l.config);
            if !report.errors.is_empty() {
                for e in &report.errors {
                    eprintln!("error: {e}");
                }
                return ExitCode::FAILURE;
            }
        }
        Err(errs) => {
            for e in &errs {
                eprintln!("error: {e}");
            }
            return ExitCode::FAILURE;
        }
    }
    let written = match output {
        Some(p) => std::fs::write(p, &im.toml).map_err(|e| format!("{}: {e}", p.display())),
        None => write!(io::stdout().lock(), "{}", im.toml).map_err(|e| e.to_string()),
    };
    if let Err(e) = written {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("imported from {from}: {}", im.counts);
    for n in &im.notes {
        eprintln!("  - {n}");
    }
    ExitCode::SUCCESS
}

fn run_import_zone(file: &Path, origin: Option<&str>, output: Option<&Path>) -> ExitCode {
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {}: {e}", file.display());
            return ExitCode::FAILURE;
        }
    };
    let im = import::parse_zone(&text, origin);
    let toml = import::to_toml(&im, &file.display().to_string());
    // The result must load as config, with valid record values.
    match Loader::new().toml_str("import", toml.clone()).load() {
        Ok(l) => {
            let (_, report) = LocalData::from_config(&l.config);
            if !report.errors.is_empty() {
                for e in &report.errors {
                    eprintln!("error: {e}");
                }
                return ExitCode::FAILURE;
            }
        }
        Err(errs) => {
            for e in &errs {
                eprintln!("error: {e}");
            }
            return ExitCode::FAILURE;
        }
    }
    let written = match output {
        Some(p) => std::fs::write(p, &toml).map_err(|e| format!("{}: {e}", p.display())),
        None => writeln!(io::stdout().lock(), "{toml}").map_err(|e| e.to_string()),
    };
    if let Err(e) = written {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!(
        "imported {} records from {} ({} lines skipped; see the header)",
        im.records.len(),
        if im.origin.is_empty() {
            "the file"
        } else {
            &im.origin
        },
        im.skipped.len()
    );
    ExitCode::SUCCESS
}

/// GETs a plain-HTTP `url` with a 3-second budget; Ok on status 200.
fn health(url: &str) -> Result<(), String> {
    use std::io::Read;
    use std::net::ToSocketAddrs;
    let rest = url
        .strip_prefix("http://")
        .ok_or("only http:// URLs are supported")?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let addr = authority
        .to_socket_addrs()
        .map_err(|e| format!("{authority}: {e}"))?
        .next()
        .ok_or_else(|| format!("{authority}: no address"))?;
    let timeout = std::time::Duration::from_secs(3);
    let mut s = std::net::TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    write!(
        s,
        "GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let mut head = [0u8; 12];
    s.read_exact(&mut head).map_err(|e| e.to_string())?;
    match &head[9..12] {
        b"200" => Ok(()),
        code => Err(format!("status {}", String::from_utf8_lossy(code))),
    }
}

fn run_self_update(channel: selfupdate::Channel, check: bool, restart: bool) -> ExitCode {
    let opts = selfupdate::Options {
        channel,
        check,
        restart,
        base_url: None,
        exe: None,
    };
    let msg = match selfupdate::run(&opts) {
        Ok(selfupdate::Outcome::UpToDate) => {
            format!("TelltaleDNS is up to date ({channel:?} channel).")
        }
        Ok(selfupdate::Outcome::Available { sha256 }) => {
            format!(
                "An update is available ({channel:?} channel, sha256 {sha256}).\n\
                 Install it with: telltale self-update --restart"
            )
        }
        Ok(selfupdate::Outcome::Updated { previous }) => {
            let mut m = format!(
                "Updated. The previous binary is kept at {}.",
                previous.display()
            );
            if !restart {
                m.push_str("\nRestart the service to use it: systemctl restart telltale");
            }
            m
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _ = writeln!(io::stdout().lock(), "{msg}");
    ExitCode::SUCCESS
}

fn init_logging() {
    let level = std::env::var("TELLTALE_LOG")
        .ok()
        .and_then(|v| v.parse::<tracing::level_filters::LevelFilter>().ok())
        .unwrap_or(tracing::level_filters::LevelFilter::INFO);
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_ansi(io::IsTerminal::is_terminal(&io::stderr()))
        .with_writer(io::stderr)
        .init();
}

fn config_files(cli: Vec<PathBuf>) -> Vec<PathBuf> {
    if !cli.is_empty() {
        return cli;
    }
    if let Ok(p) = std::env::var("TELLTALE_CONFIG") {
        return vec![PathBuf::from(p)];
    }
    if Path::new(DEFAULT_CONFIG).exists() {
        return vec![PathBuf::from(DEFAULT_CONFIG)];
    }
    Vec::new()
}

fn run(config: Vec<PathBuf>) -> io::Result<ExitCode> {
    init_logging();
    let files = config_files(config);
    let Some(cfg) = server::load(&files) else {
        return Ok(ExitCode::FAILURE);
    };
    // REQ: CLU-008 (T6.14) — one process per data directory, held until exit.
    let data_dir = Path::new(cfg.node.data_dir.as_str());
    let _lock = match datadir::lock(data_dir, std::time::Duration::from_secs(10)) {
        Ok(l) => Some(l),
        Err(datadir::LockError::Held(holder)) => {
            error!(
                data_dir = %data_dir.display(),
                holder = %holder,
                "another TelltaleDNS process is using this data directory; each process needs its own \
                 (in Kubernetes, use mode: scaled rather than more replicas of one volume)"
            );
            return Ok(ExitCode::FAILURE);
        }
        Err(datadir::LockError::Io(e)) => {
            warn!(data_dir = %data_dir.display(), error = %e, "couldn't lock the data directory; starting anyway");
            None
        }
    };
    info!(
        version = build_info::VERSION,
        commit = build_info::COMMIT,
        role = ?cfg.node.role,
        workers = server::workers(&cfg),
        config = ?files,
        "starting TelltaleDNS"
    );

    // spec/02 §3: UDP has dedicated worker threads; everything else runs on Tokio.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("telltale-rt")
        .build()?;
    rt.block_on(server::serve(files, cfg))?;
    info!("stopped");
    Ok(ExitCode::SUCCESS)
}

fn run_lists(cmd: ListsCommand) -> io::Result<ExitCode> {
    match cmd {
        ListsCommand::Fetch { config } => {
            init_logging();
            let Some(cfg) = server::load(&config_files(config)) else {
                return Ok(ExitCode::FAILURE);
            };
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            match rt.block_on(lists::fetch_once(&cfg, &mut io::stdout().lock())) {
                Ok(true) => Ok(ExitCode::SUCCESS),
                Ok(false) => Ok(ExitCode::FAILURE),
                Err(e) => {
                    eprintln!("error: {e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        ListsCommand::Compile { config, threads } => {
            let Some(cfg) = server::load(&config_files(config)) else {
                return Ok(ExitCode::FAILURE);
            };
            match lists::compile_now(&cfg, threads, &mut io::stdout().lock()) {
                Ok(true) => Ok(ExitCode::SUCCESS),
                Ok(false) => Ok(ExitCode::FAILURE),
                Err(e) => {
                    eprintln!("error: {e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        ListsCommand::Check {
            config,
            lists,
            rules,
        } => {
            let Some(cfg) = server::load(&config_files(config)) else {
                return Ok(ExitCode::FAILURE);
            };
            match lists::check(&cfg, &lists, rules, &mut io::stdout().lock()) {
                Ok(true) => Ok(ExitCode::SUCCESS),
                Ok(false) => Ok(ExitCode::FAILURE),
                Err(e) => {
                    eprintln!("error: {e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

fn run_auth(command: AuthCommand) -> ExitCode {
    let done = match command {
        AuthCommand::SetupToken { config } => {
            let Some(cfg) = server::load(&config_files(config)) else {
                return ExitCode::FAILURE;
            };
            auth_setup::print_setup_token(&cfg)
        }
        AuthCommand::HashPassword => auth_setup::hash_password(),
    };
    match done {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_audit(command: AuditCommand) -> ExitCode {
    let (config, verify, limit, action) = match command {
        AuditCommand::Verify { config } => (config, true, 0, None),
        AuditCommand::List {
            config,
            limit,
            action,
        } => (config, false, limit, action),
    };
    let Some(cfg) = server::load(&config_files(config)) else {
        return ExitCode::FAILURE;
    };
    let done = if verify {
        auth_setup::verify_audit(&cfg)
    } else {
        auth_setup::list_audit(&cfg, limit, action.as_deref())
    };
    match done {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_explain(
    name: &str,
    client: std::net::IpAddr,
    qtype: &str,
    mac: Option<&str>,
    client_id: Option<&str>,
    json: bool,
    config: Vec<PathBuf>,
) -> ExitCode {
    let Some(qtype_code) = telltale_proto::rtype::from_name(qtype) else {
        eprintln!("error: unknown query type `{qtype}`");
        return ExitCode::FAILURE;
    };
    let mac = match mac.map(telltale_config::MatchKey::parse) {
        None => None,
        Some(Ok(telltale_config::MatchKey::Mac(m))) => Some(m),
        Some(_) => {
            eprintln!("error: --mac takes a MAC address like aa:bb:cc:dd:ee:ff");
            return ExitCode::FAILURE;
        }
    };
    let Some(cfg) = server::load(&config_files(config)) else {
        return ExitCode::FAILURE;
    };
    let req = explain::Request {
        name,
        qtype: qtype_code,
        client,
        mac,
        client_id,
    };
    match explain::run_cli(&cfg, &req, qtype, json, &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_config(cmd: ConfigCommand) -> io::Result<ExitCode> {
    let mut out = io::stdout().lock();
    match cmd {
        ConfigCommand::Schema => {
            let schema = serde_json::to_string_pretty(&telltale_config::json_schema())
                .map_err(io::Error::other)?;
            writeln!(out, "{schema}")?;
            Ok(ExitCode::SUCCESS)
        }
        ConfigCommand::Check {
            files,
            no_env,
            print,
        } => {
            let mut loader = files.iter().fold(Loader::new(), Loader::file);
            if !no_env {
                loader = loader.process_env();
            }
            match loader.load() {
                Ok(cfg) => {
                    for w in &cfg.warnings {
                        eprintln!("warning: {w}");
                    }
                    // Record values and hosts files are checked too (DNS-010).
                    let (_, report) = LocalData::from_config(&cfg.config);
                    for w in &report.warnings {
                        eprintln!("warning: {w}");
                    }
                    if !report.errors.is_empty() {
                        for e in &report.errors {
                            eprintln!("error: {e}");
                        }
                        eprintln!("config invalid: {} error(s)", report.errors.len());
                        return Ok(ExitCode::FAILURE);
                    }
                    if print {
                        let text = toml::to_string(&cfg.config).map_err(io::Error::other)?;
                        write!(out, "{text}")?;
                    } else {
                        writeln!(out, "config OK")?;
                    }
                    Ok(ExitCode::SUCCESS)
                }
                Err(errors) => {
                    for e in &errors {
                        eprintln!("error: {e}");
                    }
                    eprintln!("config invalid: {} error(s)", errors.len());
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

fn run_presets(cmd: PresetsCommand) -> io::Result<ExitCode> {
    use telltale_upstream::Protocol;
    use telltale_upstream::presets::{ExpandOptions, catalog, find};

    let mut out = io::stdout().lock();
    match cmd {
        PresetsCommand::List => {
            let presets = catalog().map_err(io::Error::other)?;
            writeln!(
                out,
                "{:<20} {:<42} {:<8} {:<6} {:<4} PROTOCOLS",
                "ID", "NAME", "FILTERS", "DNSSEC", "ECS"
            )?;
            for p in presets {
                let yn = |b: bool| if b { "yes" } else { "no" };
                let filtering = format!("{:?}", p.filtering).to_lowercase();
                writeln!(
                    out,
                    "{:<20} {:<42} {:<8} {:<6} {:<4} {}",
                    p.id,
                    p.name,
                    filtering,
                    yn(p.dnssec),
                    yn(p.ecs),
                    p.protocols().join(",")
                )?;
            }
            Ok(ExitCode::SUCCESS)
        }
        PresetsCommand::Show {
            id,
            proto,
            params,
            no_ipv6,
            group,
        } => {
            let Some(preset) = find(&id) else {
                eprintln!("error: unknown preset `{id}` (see `telltale presets list`)");
                return Ok(ExitCode::FAILURE);
            };
            let mut opts = ExpandOptions {
                no_ipv6,
                group,
                ..ExpandOptions::default()
            };
            for p in &proto {
                opts.protocols.push(match p.as_str() {
                    "udp" => Protocol::Udp,
                    "tcp" => Protocol::Tcp,
                    "tls" | "dot" => Protocol::Tls,
                    "https" | "doh" => Protocol::Https,
                    other => {
                        eprintln!("error: unknown protocol `{other}` (udp, tcp, tls, https)");
                        return Ok(ExitCode::FAILURE);
                    }
                });
            }
            for kv in &params {
                let Some((k, v)) = kv.split_once('=') else {
                    eprintln!("error: --param expects KEY=VALUE, got `{kv}`");
                    return Ok(ExitCode::FAILURE);
                };
                opts.params.insert(k.to_string(), v.to_string());
            }
            match preset.expand(&opts) {
                Ok(exp) => {
                    writeln!(out, "# {} — {}", preset.name, preset.homepage)?;
                    for (url, why) in &exp.skipped {
                        writeln!(out, "# skipped {url}: {why}")?;
                    }
                    write!(out, "{}", exp.to_toml().map_err(io::Error::other)?)?;
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}
