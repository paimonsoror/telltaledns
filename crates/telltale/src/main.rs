//! TelltaleDNS binary: CLI, role wiring, and signal handling (`spec/02-architecture.md` §1).

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("version" | "--version" | "-V") | None => {
            #[allow(clippy::print_stdout)]
            {
                println!("telltale {}", env!("CARGO_PKG_VERSION"));
            }
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("telltale: unknown command `{other}`");
            ExitCode::from(2)
        }
    }
}
