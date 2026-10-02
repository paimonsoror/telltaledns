//! TelltaleDNS binary: CLI, role wiring, and signal handling (`spec/02-architecture.md` §1).

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use telltale_config::Loader;

/// TelltaleDNS — see every question, answer on your terms.
#[derive(Debug, Parser)]
#[command(name = "telltale", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect and validate configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
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
        Command::Config { command } => run_config(command),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("telltale: {e}");
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
