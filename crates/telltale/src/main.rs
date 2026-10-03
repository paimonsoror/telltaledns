//! TelltaleDNS binary: CLI, role wiring, and signal handling (`spec/02-architecture.md` §1).

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

mod pipeline;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use telltale_cache::{Cache, CachePolicy};
use telltale_config::{ListenProto, Loader};
use telltale_net::{TcpConfig, TcpServer, UdpConfig, UdpListener};
use telltale_policy::LocalData;
use telltale_upstream::Router;
use tracing::{error, info, warn};

use crate::pipeline::{Handler, Pipeline, Settings};

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
    let loaded = match files
        .iter()
        .fold(Loader::new(), Loader::file)
        .process_env()
        .load()
    {
        Ok(l) => l,
        Err(errors) => {
            for e in &errors {
                error!("config: {e}");
            }
            return Ok(ExitCode::FAILURE);
        }
    };
    for w in &loaded.warnings {
        warn!("config: {w}");
    }
    let cfg = loaded.config;
    let workers = match cfg.node.workers {
        0 => telltale_net::default_workers(),
        n => usize::from(n),
    };
    info!(
        version = env!("CARGO_PKG_VERSION"),
        role = ?cfg.node.role,
        workers,
        config = ?files,
        "starting TelltaleDNS"
    );

    // spec/02 §3: UDP has dedicated worker threads; everything else runs on Tokio.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("telltale-rt")
        .build()?;
    rt.block_on(serve(&cfg, workers))?;
    info!("stopped");
    Ok(ExitCode::SUCCESS)
}

fn cache_policy(c: &telltale_config::CacheConfig, workers: usize) -> CachePolicy {
    CachePolicy {
        max_bytes: usize::try_from(c.max_bytes.bytes()).unwrap_or(usize::MAX),
        max_entries: c.max_entries as usize,
        min_ttl: c.min_ttl,
        max_ttl: c.max_ttl,
        negative_ttl_max: c.negative_ttl_max,
        servfail_ttl: c.servfail_ttl,
        serve_stale: c.serve_stale,
        stale_max_age: c.stale_max_age,
        stale_answer_ttl: c.stale_answer_ttl,
        prefetch: c.prefetch,
        prefetch_threshold_pct: c.prefetch_threshold_pct,
        prefetch_min_hits: c.prefetch_min_hits,
        // spec/03 §4: power of two >= 4 × workers, at least 64.
        shards: (workers * 4).max(64),
    }
}

async fn serve(cfg: &telltale_config::Config, workers: usize) -> io::Result<()> {
    // spec/04 §7: tag outbound queries so a forwarding loop back to us is detectable.
    telltale_upstream::set_node_tag(rand::random());
    let router = match Router::from_config(cfg) {
        Ok(r) => Arc::new(r),
        Err(errors) => {
            for e in &errors {
                error!("upstreams: {e}");
            }
            return Err(io::Error::other("invalid upstream configuration"));
        }
    };
    for up in router.upstreams() {
        info!(name = %up.name, endpoint = %up.endpoint, "upstream");
    }
    let health = tokio::spawn(telltale_upstream::active_health_checks(
        router.upstreams().to_vec(),
        telltale_upstream::HEALTH_CHECK_INTERVAL,
    ));
    let cache = Arc::new(Cache::new(cache_policy(&cfg.cache, workers)));
    let settings = Settings {
        stale_answer_timeout: Duration::from_millis(u64::from(
            cfg.cache.stale_answer_client_timeout_ms,
        )),
        ..Settings::default()
    };
    let (local, report) = LocalData::from_config(cfg);
    for w in &report.warnings {
        warn!("local records: {w}");
    }
    if !report.errors.is_empty() {
        for e in &report.errors {
            error!("local records: {e}");
        }
        return Err(io::Error::other("invalid local records"));
    }
    if !local.is_empty() {
        info!(records = local.len(), "local records loaded");
    }
    let handler = Arc::new(Handler(Pipeline::new(
        settings,
        cache,
        router,
        Arc::new(local),
    )));
    let rt = tokio::runtime::Handle::current();
    let mut udp = Vec::new();
    let mut tcp = Vec::new();
    for l in &cfg.listen {
        let ctx = |e: io::Error| io::Error::new(e.kind(), format!("{:?} {}: {e}", l.proto, l.addr));
        match l.proto {
            ListenProto::Udp => {
                let listener = UdpListener::spawn(&UdpConfig::new(l.addr, workers), &handler, &rt)
                    .map_err(ctx)?;
                info!(addr = %listener.local_addr(), workers, "listening (udp)");
                udp.push(listener);
            }
            ListenProto::Tcp => {
                let server =
                    TcpServer::bind(TcpConfig::new(l.addr), Arc::clone(&handler)).map_err(ctx)?;
                info!(addr = %server.local_addr(), "listening (tcp)");
                tcp.push(server);
            }
            other => {
                warn!(addr = %l.addr, proto = ?other, "listener type not implemented yet; skipping");
            }
        }
    }

    // REQ: OPS-007 (partial) — stop on SIGTERM/SIGINT. Full drain + reload arrive with T1.10.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => info!(signal = "SIGTERM", "shutting down"),
        _ = tokio::signal::ctrl_c() => info!(signal = "SIGINT", "shutting down"),
    }
    for s in tcp {
        s.shutdown().await;
    }
    for l in udp {
        l.shutdown();
    }
    health.abort();
    Ok(())
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
