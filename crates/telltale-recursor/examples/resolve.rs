//! Resolves names from the root servers and prints what came back (a manual check):
//! `cargo run -p telltale-recursor --example resolve -- example.com www.wikipedia.org/AAAA`

#![allow(clippy::print_stdout, clippy::print_stderr)] // a command-line example

use std::time::Instant;

use telltale_proto::{NameBuf, rtype};
use telltale_recursor::{Recursor, Settings};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let r = Recursor::new(Settings {
        case_randomization: std::env::var_os("CASE").is_some(),
        ..Settings::default()
    });
    for arg in std::env::args().skip(1) {
        let (name, t) = arg.split_once('/').unwrap_or((&arg, "A"));
        let qtype = match t {
            "AAAA" => rtype::AAAA,
            "MX" => rtype::MX,
            "TXT" => rtype::TXT,
            "NS" => rtype::NS,
            "DS" => rtype::DS,
            "SOA" => rtype::SOA,
            _ => rtype::A,
        };
        let Ok(n) = NameBuf::from_presentation(name) else {
            eprintln!("{name}: not a name");
            continue;
        };
        let t0 = Instant::now();
        match r.resolve(n, qtype, std::env::var_os("DO").is_some()).await {
            Ok(res) => {
                println!(
                    "{name}/{t}: rcode {} in {:?} ({} answers, {} authority)",
                    res.rcode,
                    t0.elapsed(),
                    res.answer.len(),
                    res.authority.len()
                );
                for a in &res.answer {
                    let v = a.addr().map_or_else(
                        || {
                            a.target().map_or_else(
                                || format!("{} bytes", a.rdata.len()),
                                |t| t.display().to_string(),
                            )
                        },
                        |ip| ip.to_string(),
                    );
                    println!("  {} {} {} {v}", a.name.display(), a.ttl, a.rtype);
                }
            }
            Err(e) => println!("{name}/{t}: error {e} after {:?}", t0.elapsed()),
        }
    }
    println!("zone cuts cached: {}", r.cached_zones());
}
