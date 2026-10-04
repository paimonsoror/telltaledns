//! TelltaleDNS binary: CLI, role wiring, and signal handling (`spec/02-architecture.md` §1).

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

mod api_backend;
mod auth_setup;
mod explain;
mod http;
mod lists;
mod pipeline;
mod qlog_cli;
mod rollups;
mod server;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use telltale_config::Loader;
use telltale_policy::LocalData;
use tracing::info;

// REQ: OPS-001, 02 §3 — mimalloc everywhere. The static musl image would otherwise use musl's
// allocator, which roughly halved cache-hit throughput in the bench harness.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Default config file location (`spec/08` §3.4).
const DEFAULT_CONFIG: &str = "/etc/telltale/telltale.toml";

/// TelltaleDNS — see every question, answer on your terms.
#[derive(Debug, Parser)]
#[command(name = "telltale", version, about)]
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
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("telltale: {e}");
            ExitCode::FAILURE
        }
    }
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
    info!(
        version = env!("CARGO_PKG_VERSION"),
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
