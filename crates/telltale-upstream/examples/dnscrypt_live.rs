//! Resolves example.com through DNSCrypt stamps given as arguments (a manual check against
//! real servers): `cargo run -p telltale-upstream --example dnscrypt_live -- sdns://...`

#![allow(clippy::print_stdout, clippy::print_stderr)] // a command-line example

use std::time::{Duration, Instant};

use telltale_proto::{NameBuf, rtype, summarize};
use telltale_upstream::dnscrypt::{Stamp, parse_stamp};
use telltale_upstream::{
    Endpoint, Host, Protocol, Question, TlsOptions, Upstream, UpstreamOptions,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let q = Question {
        name: NameBuf::from_presentation("example.com").unwrap_or_default(),
        qtype: rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
    };
    let (mut ok, mut failed) = (0, 0);
    for arg in std::env::args().skip(1) {
        let Ok(Stamp::DnsCrypt {
            addr,
            provider_pk,
            provider_name,
        }) = parse_stamp(&arg)
        else {
            continue;
        };
        let ep = Endpoint {
            protocol: Protocol::DnsCrypt,
            host: Host::Ip(addr.ip()),
            port: addr.port(),
            path: String::new(),
        };
        let opts = UpstreamOptions {
            timeout: Duration::from_secs(3),
            dnscrypt: Some((provider_pk, provider_name.clone())),
            ..UpstreamOptions::default()
        };
        let Ok(up) = Upstream::build(1, "x", ep, &opts, &TlsOptions::default()) else {
            continue;
        };
        let t0 = Instant::now();
        match up.exchange(&q, Duration::from_secs(3)).await {
            Ok(r) => {
                ok += 1;
                let s = summarize(&r).map_or((99, 0), |s| (s.rcode, s.answers));
                println!(
                    "ok   {addr} {provider_name}: rcode {} answers {} in {:?}",
                    s.0,
                    s.1,
                    t0.elapsed()
                );
            }
            Err(e) => {
                failed += 1;
                println!("FAIL {addr} {provider_name}: {e}");
            }
        }
    }
    println!("{ok} ok, {failed} failed");
}
