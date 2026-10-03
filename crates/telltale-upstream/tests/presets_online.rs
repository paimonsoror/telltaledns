//! T1.6 AC: every preset endpoint resolves example.com (online; nightly; flaky-tolerant).
//!
//! Run: `cargo test -p telltale-upstream --test presets_online -- --ignored --nocapture`
//! Templated presets (NextDNS, Control D custom) need an account and are skipped; DoQ endpoints
//! are skipped until DoQ lands; IPv6 endpoints are skipped when the host has no IPv6 route.

#![allow(clippy::unwrap_used, clippy::print_stdout)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use telltale_proto::{NameBuf, rcode, rtype, summarize};
use telltale_upstream::presets::catalog;
use telltale_upstream::{Bootstrap, Host, Question, TlsOptions, Upstream, UpstreamOptions};

const TRIES: usize = 3;

async fn has_ipv6() -> bool {
    let target: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
    matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(target)
        )
        .await,
        Ok(Ok(_))
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "online: run nightly or by hand with --ignored"]
async fn ups_004_every_preset_endpoint_resolves_example_com() {
    let v6 = has_ipv6().await;
    println!("IPv6 available: {v6}");
    let q = Question {
        name: NameBuf::from_presentation("example.com").unwrap(),
        qtype: rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
    };
    let mut failures = Vec::new();
    let mut checked = 0;
    for preset in catalog().unwrap() {
        if !preset.params.is_empty() {
            println!(
                "skip  {:<20} (needs an account: {})",
                preset.id,
                preset.params.join(", ")
            );
            continue;
        }
        let bootstrap: Vec<SocketAddr> = {
            let own: Vec<_> = preset
                .endpoint
                .iter()
                .filter_map(|e| telltale_upstream::Endpoint::parse(&e.url).ok())
                .filter_map(|e| e.socket_addr())
                .filter(|a| a.is_ipv4() && a.port() == 53)
                .collect();
            if own.is_empty() {
                vec!["9.9.9.9:53".parse().unwrap()]
            } else {
                own
            }
        };
        let bs = Arc::new(Bootstrap::new(bootstrap));
        for (ep, parsed) in preset
            .endpoints(&std::collections::BTreeMap::default())
            .unwrap()
        {
            let Ok(endpoint) = parsed else {
                println!("skip  {:<20} {} (not supported yet)", preset.id, ep.url);
                continue;
            };
            if !v6 && matches!(endpoint.host, Host::Ip(ip) if ip.is_ipv6()) {
                println!("skip  {:<20} {} (no IPv6 route)", preset.id, ep.url);
                continue;
            }
            checked += 1;
            let opts = UpstreamOptions {
                timeout: Duration::from_secs(3),
                tls_server_name: ep.tls_server_name.clone(),
                bootstrap: Some(Arc::clone(&bs)),
                ..UpstreamOptions::default()
            };
            let up = match Upstream::build(1, &preset.id, endpoint, &opts, &TlsOptions::default()) {
                Ok(u) => u,
                Err(e) => {
                    failures.push(format!("{} {}: build: {e}", preset.id, ep.url));
                    continue;
                }
            };
            let mut last = String::new();
            let mut ok = false;
            for _ in 0..TRIES {
                match up.exchange(&q, Duration::from_secs(3)).await {
                    Ok(resp)
                        if summarize(&resp)
                            .is_ok_and(|s| s.rcode == rcode::NOERROR && s.answers > 0) =>
                    {
                        ok = true;
                        break;
                    }
                    Ok(resp) => {
                        last = format!("unexpected answer {:?}", summarize(&resp).map(|s| s.rcode));
                    }
                    Err(e) => last = e.to_string(),
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            println!(
                "{}  {:<20} {}",
                if ok { "ok  " } else { "FAIL" },
                preset.id,
                ep.url
            );
            if !ok {
                failures.push(format!("{} {}: {last}", preset.id, ep.url));
            }
        }
    }
    println!("checked {checked} endpoints, {} failed", failures.len());
    assert!(
        failures.is_empty(),
        "preset endpoints failing:\n{}",
        failures.join("\n")
    );
}
