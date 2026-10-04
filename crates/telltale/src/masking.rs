//! Masked-client-IP detector (REQ: OPS-003, `spec/08` §3.2, ADR-037).
//!
//! Per-client analytics are worthless when every query appears to come from a node, a
//! Docker bridge, or a forwarding router. Every evaluation reads the aggregator's latest
//! 10-minute window: when at least [`MIN_QUERIES`] queries were seen and more than 90% of
//! them came from ≤ 3 *infrastructure* addresses, client IPs appear masked.
//!
//! Infrastructure = loopback, this host's default gateways (a Docker bridge or kube-proxy
//! SNAT shows up as the pod's gateway; a router forwarding DNS is the LAN's gateway), the
//! node addresses in `TELLTALE_NODE_IPS` (the Helm chart sets it from the downward API), and
//! `[clients] infrastructure`. Evaluation runs only for the API and metrics scrapes, never
//! on the query path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};

use telltale_config::Cidr;
use telltale_telemetry::recent::ClientWindow;

/// Fewer queries than this in a window never trigger the warning.
pub(crate) const MIN_QUERIES: u64 = 100;
/// Infrastructure addresses that may carry the traffic.
const MAX_SOURCES: usize = 3;

/// The finding, for the API, the UI banner, and the metric.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Masked {
    /// Share of the window's queries from the infrastructure sources, in percent.
    pub(crate) share_percent: u32,
    /// The infrastructure addresses, heaviest first.
    pub(crate) sources: Vec<String>,
    pub(crate) queries: u64,
    pub(crate) window_start_s: u64,
}

/// Remembers the last result so a change is logged once.
#[derive(Debug, Default)]
pub(crate) struct Detector {
    masked: AtomicBool,
}

impl Detector {
    /// Evaluates the latest window; logs when the state changes.
    pub(crate) fn check(&self, w: Option<&ClientWindow>, configured: &[Cidr]) -> Option<Masked> {
        let infra = infrastructure(configured);
        let found = w.and_then(|w| assess(w, &infra));
        let was = self.masked.swap(found.is_some(), Ordering::Relaxed);
        match (&found, was) {
            (Some(m), false) => tracing::warn!(
                sources = ?m.sources,
                share_percent = m.share_percent,
                "client IPs appear masked: most queries come from infrastructure addresses, \
                 so per-device analytics and rules see those instead of devices (see docs: \
                 Seeing real client IPs)"
            ),
            (None, true) => tracing::info!("client IPs no longer appear masked"),
            _ => {}
        }
        found
    }
}

/// Whether `w` shows masked client IPs, given the infrastructure networks.
pub(crate) fn assess(w: &ClientWindow, infra: &[Cidr]) -> Option<Masked> {
    if w.total < MIN_QUERIES {
        return None;
    }
    let hits: Vec<(IpAddr, u64)> = w
        .top
        .iter()
        .take(MAX_SOURCES)
        .map(|(ip, n)| (ip_of(*ip), *n))
        .filter(|(ip, _)| infra.iter().any(|c| c.contains(*ip)))
        .collect();
    let n: u64 = hits.iter().map(|(_, n)| n).sum();
    // REQ: OPS-003 — "> 90% of queries come from ≤ 3 IPs inside the pod/node CIDRs".
    (u128::from(n) * 10 > u128::from(w.total) * 9).then(|| Masked {
        share_percent: u32::try_from(n * 100 / w.total).unwrap_or(100),
        sources: hits.iter().map(|(ip, _)| ip.to_string()).collect(),
        queries: w.total,
        window_start_s: w.start_s,
    })
}

fn ip_of(mapped: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(mapped);
    v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
}

/// Loopback, default gateways, `TELLTALE_NODE_IPS`, and the configured networks.
pub(crate) fn infrastructure(configured: &[Cidr]) -> Vec<Cidr> {
    let mut out = vec![
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
            prefix: 8,
        },
        Cidr {
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix: 128,
        },
    ];
    let host = |addr| Cidr {
        addr,
        prefix: if matches!(addr, IpAddr::V4(_)) {
            32
        } else {
            128
        },
    };
    if let Ok(t) = std::fs::read_to_string("/proc/net/route") {
        out.extend(gateways_v4(&t).into_iter().map(|a| host(IpAddr::V4(a))));
    }
    if let Ok(t) = std::fs::read_to_string("/proc/net/ipv6_route") {
        out.extend(gateways_v6(&t).into_iter().map(|a| host(IpAddr::V6(a))));
    }
    if let Ok(v) = std::env::var("TELLTALE_NODE_IPS") {
        out.extend(node_ips(&v).into_iter().map(host));
    }
    out.extend_from_slice(configured);
    out
}

/// `TELLTALE_NODE_IPS`: addresses separated by commas or spaces; junk is skipped.
fn node_ips(v: &str) -> Vec<IpAddr> {
    v.split([',', ' '])
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

/// Gateways of the default routes in `/proc/net/route` (little-endian hex fields).
fn gateways_v4(table: &str) -> Vec<Ipv4Addr> {
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (dest, gw, mask) = (f.get(1)?, f.get(2)?, f.get(7)?);
            if *dest != "00000000" || *mask != "00000000" {
                return None;
            }
            let g = u32::from_str_radix(gw, 16).ok().filter(|g| *g != 0)?;
            Some(Ipv4Addr::from(g.swap_bytes()))
        })
        .collect()
}

/// Gateways of the default routes in `/proc/net/ipv6_route` (big-endian hex fields).
fn gateways_v6(table: &str) -> Vec<Ipv6Addr> {
    table
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (dest, plen, gw) = (f.first()?, f.get(1)?, f.get(4)?);
            if dest.chars().any(|c| c != '0') || *plen != "00" {
                return None;
            }
            let g = u128::from_str_radix(gw, 16).ok().filter(|g| *g != 0)?;
            Some(Ipv6Addr::from(g))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapped(ip: &str) -> [u8; 16] {
        match ip.parse::<IpAddr>().unwrap() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        }
    }

    fn window(total: u64, top: &[(&str, u64)]) -> ClientWindow {
        ClientWindow {
            start_s: 600,
            total,
            clients: top.len(),
            top: top.iter().map(|(ip, n)| (mapped(ip), *n)).collect(),
        }
    }

    fn infra() -> Vec<Cidr> {
        vec![
            Cidr::parse("10.42.0.0/16").unwrap(),
            Cidr::parse("192.168.5.2").unwrap(),
        ]
    }

    #[test]
    fn ops_003_masked_when_infrastructure_carries_over_90_percent() {
        let w = window(
            1000,
            &[
                ("10.42.0.1", 700),
                ("192.168.5.2", 250),
                ("192.168.5.50", 50),
            ],
        );
        let m = assess(&w, &infra()).unwrap();
        assert_eq!(m.share_percent, 95);
        assert_eq!(m.sources, ["10.42.0.1", "192.168.5.2"]);
        assert_eq!(m.queries, 1000);
    }

    #[test]
    fn ops_003_real_devices_are_not_masked() {
        // A household with two busy devices: concentrated, but not infrastructure.
        let w = window(1000, &[("192.168.5.50", 600), ("192.168.5.51", 390)]);
        assert_eq!(assess(&w, &infra()), None);
        // Exactly 90% is not "more than 90%".
        let w = window(1000, &[("10.42.0.1", 900), ("192.168.5.50", 100)]);
        assert_eq!(assess(&w, &infra()), None);
        // Too few queries to judge.
        let w = window(MIN_QUERIES - 1, &[("10.42.0.1", MIN_QUERIES - 1)]);
        assert_eq!(assess(&w, &infra()), None);
    }

    #[test]
    fn ops_003_only_three_sources_count() {
        let w = window(
            1000,
            &[
                ("10.42.0.1", 300),
                ("10.42.0.2", 300),
                ("10.42.0.3", 300),
                ("10.42.0.4", 100),
            ],
        );
        assert_eq!(assess(&w, &infra()), None);
    }

    #[test]
    fn ops_003_ipv6_infrastructure() {
        let infra = vec![Cidr::parse("fd00::/8").unwrap()];
        let w = window(200, &[("fd00::1", 199), ("2001:db8::5", 1)]);
        assert_eq!(assess(&w, &infra).map(|m| m.share_percent), Some(99));
    }

    #[test]
    fn ops_003_parses_proc_routes() {
        let v4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                  eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
                  eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        assert_eq!(gateways_v4(v4), [Ipv4Addr::new(172, 17, 0, 1)]);
        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n\
                  fd000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n";
        assert_eq!(gateways_v6(v6), ["fe80::1".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(
            node_ips("192.168.5.2, fd00::2 junk"),
            [
                "192.168.5.2".parse::<IpAddr>().unwrap(),
                "fd00::2".parse().unwrap()
            ]
        );
    }

    #[test]
    fn ops_003_detector_reports_changes() {
        let d = Detector::default();
        let masked = window(1000, &[("127.0.0.1", 1000)]);
        assert!(d.check(Some(&masked), &[]).is_some());
        assert!(d.masked.load(Ordering::Relaxed));
        assert!(d.check(None, &[]).is_none());
        assert!(!d.masked.load(Ordering::Relaxed));
    }
}
