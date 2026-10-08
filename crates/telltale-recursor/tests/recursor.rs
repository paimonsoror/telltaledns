//! REQ: DNS-012 — the iterative resolver against a small fake DNS tree on loopback addresses
//! (127.0.0.2 = root, .3 = com, .4 = example.com, .5 = other.net, .6 = outside.com, whose
//! server name is under example.com, .7 = a lame server), all on one port.

#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use telltale_proto::{HEADER_LEN, NameBuf, rcode, read_name, rtype};
use telltale_recursor::{Recursor, Settings};
use tokio::net::UdpSocket;

/// A zone: its records, its delegations (child, server name, glue), and quirks.
#[derive(Clone, Default)]
#[allow(clippy::struct_excessive_bools)] // independent quirks
struct Zone {
    origin: &'static str,
    records: Vec<(&'static str, u16, Vec<u8>)>,
    cuts: Vec<(&'static str, &'static str, Option<[u8; 4]>)>,
    /// Answers in lowercase whatever case was asked (breaks 0x20).
    lowercase: bool,
    /// Adds a record for another zone's name to every answer (a poisoning attempt).
    poison: bool,
    /// Always refers back to the root (lame).
    lame: bool,
    /// Before every answer, sends a forged one first: the question in lowercase and the
    /// address 6.6.6.6 (an off-path spoofer who guessed the ID and port, but not the case).
    spoof: bool,
    /// Milliseconds to wait before answering (changeable while running).
    delay_ms: Option<Arc<AtomicU64>>,
}

fn wire(name: &str) -> Vec<u8> {
    NameBuf::from_presentation(name).unwrap().as_wire().to_vec()
}

fn rr(out: &mut Vec<u8>, name: &str, t: u16, ttl: u32, rdata: &[u8]) {
    out.extend(wire(name));
    out.extend(t.to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out.extend(ttl.to_be_bytes());
    out.extend(u16::try_from(rdata.len()).unwrap().to_be_bytes());
    out.extend(rdata);
}

fn soa(origin: &str) -> Vec<u8> {
    let mut d = wire(&format!("ns.{origin}"));
    d.extend(wire(&format!("admin.{origin}")));
    for v in [1u32, 3600, 600, 86400, 60] {
        d.extend(v.to_be_bytes());
    }
    d
}

fn under(name: &str, zone: &str) -> bool {
    zone.is_empty() || name == zone || name.ends_with(&format!(".{zone}"))
}

/// The response of `z` to `query`.
fn respond(z: &Zone, query: &[u8]) -> Vec<u8> {
    let mut n = NameBuf::default();
    let end = read_name(query, HEADER_LEN, &mut n).unwrap();
    let qtype = u16::from_be_bytes([query[end], query[end + 1]]);
    let qname = n.display().to_string();
    let qname = qname.trim_end_matches('.').to_owned();
    let mut question = query[HEADER_LEN..end + 4].to_vec();
    if z.lowercase {
        question.make_ascii_lowercase();
    }
    let (mut an, mut ns, mut ad) = (Vec::new(), Vec::new(), Vec::new());
    let (mut na, mut nn, mut nd) = (0u16, 0u16, 0u16);
    let mut aa = true;
    let mut rc = rcode::NOERROR;
    if z.lame {
        aa = false;
        rr(&mut ns, "", rtype::NS, 3600, &wire("a.root-servers.net"));
        nn += 1;
    } else if let Some(child) = z
        .cuts
        .iter()
        .map(|c| c.0)
        .filter(|c| under(&qname, c) && !(qtype == rtype::DS && qname == *c))
        .max_by_key(|c| c.len())
    {
        aa = false;
        for (c, server, glue) in z.cuts.iter().filter(|x| x.0 == child) {
            rr(&mut ns, c, rtype::NS, 3600, &wire(server));
            nn += 1;
            if let Some(g) = glue {
                rr(&mut ad, server, rtype::A, 3600, g);
                nd += 1;
            }
        }
    } else {
        let at: Vec<&(&str, u16, Vec<u8>)> = z.records.iter().filter(|r| r.0 == qname).collect();
        if let Some(c) = at
            .iter()
            .find(|r| r.1 == rtype::CNAME && qtype != rtype::CNAME)
        {
            rr(&mut an, c.0, rtype::CNAME, 300, &c.2);
            na += 1;
        } else if at.iter().any(|r| r.1 == qtype) {
            for r in at.iter().filter(|r| r.1 == qtype) {
                rr(&mut an, r.0, r.1, 300, &r.2);
                na += 1;
                // Glue for NS answers, from this zone's own records.
                if qtype == rtype::NS {
                    let mut target = NameBuf::default();
                    read_name(&r.2, 0, &mut target).unwrap();
                    let t = target.display().to_string();
                    let t = t.trim_end_matches('.');
                    for g in z.records.iter().filter(|g| g.0 == t && g.1 == rtype::A) {
                        rr(&mut ad, g.0, g.1, 300, &g.2);
                        nd += 1;
                    }
                }
            }
            if z.poison {
                rr(&mut an, "www.victim.net", rtype::A, 300, &[6, 6, 6, 6]);
                na += 1;
            }
        } else if !at.is_empty()
            || z.records
                .iter()
                .any(|r| r.0.ends_with(&format!(".{qname}")))
        {
            rr(&mut ns, z.origin, rtype::SOA, 60, &soa(z.origin));
            nn += 1;
        } else {
            rc = rcode::NXDOMAIN;
            rr(&mut ns, z.origin, rtype::SOA, 60, &soa(z.origin));
            nn += 1;
        }
    }
    let mut out = Vec::new();
    out.extend(&query[..2]);
    let flags: u16 = 0x8000 | if aa { 0x0400 } else { 0 } | rc;
    out.extend(flags.to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out.extend(na.to_be_bytes());
    out.extend(nn.to_be_bytes());
    out.extend(nd.to_be_bytes());
    out.extend(question);
    out.extend(an);
    out.extend(ns);
    out.extend(ad);
    out
}

type Log = Arc<Mutex<Vec<(u8, String)>>>;

async fn serve(ip: u8, port: u16, z: Zone, log: Log) {
    let s = UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, ip)),
        port,
    ))
    .await
    .unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else {
                return;
            };
            let q = &buf[..n];
            let mut name = NameBuf::default();
            if let Ok(end) = read_name(q, HEADER_LEN, &mut name) {
                // Raw bytes, case as asked.
                let raw: String = q[HEADER_LEN..end]
                    .iter()
                    .map(|b| {
                        if b.is_ascii_graphic() {
                            char::from(*b)
                        } else {
                            '.'
                        }
                    })
                    .collect();
                log.lock().unwrap().push((ip, raw));
            }
            if let Some(d) = &z.delay_ms {
                let ms = d.load(Ordering::Relaxed);
                if ms > 0 {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
            }
            if z.spoof {
                let mut fake = z.clone();
                fake.lowercase = true;
                for r in &mut fake.records {
                    if r.1 == rtype::A {
                        r.2 = a([6, 6, 6, 6]);
                    }
                }
                let _ = s.send_to(&respond(&fake, q), from).await;
            }
            let _ = s.send_to(&respond(&z, q), from).await;
        }
    });
}

fn a(ip: [u8; 4]) -> Vec<u8> {
    ip.to_vec()
}

/// Starts the tree; returns the resolver's settings and the query log.
async fn tree(mutate: impl FnOnce(&mut Vec<(u8, Zone)>)) -> (Settings, Log) {
    // A free port on 127.0.0.2, used on every address.
    let probe = std::net::UdpSocket::bind("127.0.0.2:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut zones = vec![
        (
            2,
            Zone {
                origin: "",
                cuts: vec![
                    ("com", "ns.com", Some([127, 0, 0, 3])),
                    ("net", "ns.com", Some([127, 0, 0, 3])),
                ],
                ..Zone::default()
            },
        ),
        (
            3,
            Zone {
                origin: "com",
                cuts: vec![
                    ("example.com", "ns1.example.com", Some([127, 0, 0, 4])),
                    ("other.net", "ns.other.net", Some([127, 0, 0, 5])),
                    // Out of bailiwick for com: no glue, so the resolver looks it up.
                    ("outside.com", "ns.outside-dns.example.com", None),
                    ("lame.com", "ns.lame.com", Some([127, 0, 0, 7])),
                ],
                ..Zone::default()
            },
        ),
        (
            4,
            Zone {
                origin: "example.com",
                records: vec![
                    ("www.example.com", rtype::A, a([10, 0, 0, 1])),
                    ("alias.example.com", rtype::CNAME, wire("www.other.net")),
                    ("ns.outside-dns.example.com", rtype::A, a([127, 0, 0, 6])),
                    ("deep.ent.example.com", rtype::A, a([10, 0, 0, 9])),
                ],
                ..Zone::default()
            },
        ),
        (
            5,
            Zone {
                origin: "other.net",
                records: vec![("www.other.net", rtype::A, a([10, 0, 0, 2]))],
                ..Zone::default()
            },
        ),
        (
            6,
            Zone {
                origin: "outside.com",
                records: vec![("www.outside.com", rtype::A, a([10, 0, 0, 3]))],
                ..Zone::default()
            },
        ),
        (
            7,
            Zone {
                origin: "lame.com",
                lame: true,
                ..Zone::default()
            },
        ),
    ];
    mutate(&mut zones);
    let log: Log = Arc::default();
    for (ip, z) in zones {
        serve(ip, port, z, Arc::clone(&log)).await;
    }
    let s = Settings {
        roots: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))],
        port,
        server_timeout: Duration::from_millis(300),
        // The query-log assertions count every query: priming has its own test.
        prime: false,
        ..Settings::default()
    };
    (s, log)
}

fn name(s: &str) -> NameBuf {
    NameBuf::from_presentation(s).unwrap()
}

fn addrs(r: &telltale_recursor::Resolved) -> Vec<IpAddr> {
    r.answer
        .iter()
        .filter_map(telltale_recursor::msg::Rr::addr)
        .collect()
}

/// REQ: DNS-012 — referrals from the root down, with QNAME minimization: the root sees only
/// `com`, com sees only `example.com`; the delegation is cached for the next name.
#[tokio::test]
async fn dns_012_resolves_with_qname_minimization() {
    let (s, log) = tree(|_| {}).await;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(
        (res.rcode, addrs(&res)),
        (rcode::NOERROR, vec![IpAddr::from([10, 0, 0, 1])])
    );
    let seen = log.lock().unwrap().clone();
    let at = |ip: u8| {
        seen.iter()
            .filter(|(i, _)| *i == ip)
            .map(|(_, n)| n.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        at(2),
        vec![".com.".to_owned()],
        "the root saw only com: {seen:?}"
    );
    assert_eq!(
        at(3),
        vec![".example.com.".to_owned()],
        "com saw only example.com: {seen:?}"
    );
    // The next name under example.com goes straight to its server.
    log.lock().unwrap().clear();
    let res = r
        .resolve(name("deep.ent.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 9])]);
    assert!(
        log.lock().unwrap().iter().all(|(ip, _)| *ip == 4),
        "{:?}",
        log.lock().unwrap()
    );
}

/// REQ: DNS-012 — a CNAME into another zone is chased from that zone's servers; an
/// out-of-bailiwick server name is looked up; NXDOMAIN and NODATA carry the SOA.
#[tokio::test]
async fn dns_012_cnames_server_names_and_negative_answers() {
    let (s, _) = tree(|_| {}).await;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("alias.example.com"), rtype::A, false)
        .await
        .unwrap();
    let types: Vec<u16> = res.answer.iter().map(|x| x.rtype).collect();
    assert_eq!(types, vec![rtype::CNAME, rtype::A]);
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 2])]);
    let res = r
        .resolve(name("www.outside.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(
        addrs(&res),
        vec![IpAddr::from([10, 0, 0, 3])],
        "via ns.outside-dns.example.com"
    );
    let res = r
        .resolve(name("nope.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(res.rcode, rcode::NXDOMAIN);
    assert_eq!(
        res.authority.iter().map(|x| x.rtype).collect::<Vec<_>>(),
        vec![rtype::SOA]
    );
    let res = r
        .resolve(name("www.example.com"), rtype::AAAA, false)
        .await
        .unwrap();
    assert_eq!(
        (res.rcode, res.answer.len(), res.authority.len()),
        (rcode::NOERROR, 0, 1)
    );
}

/// REQ: DNS-012 — records for names outside the answering server's zone are dropped
/// (cache poisoning), and a lame delegation fails instead of looping.
#[tokio::test]
async fn dns_012_bailiwick_and_lame_servers() {
    let (s, _) = tree(|z| z[2].1.poison = true).await;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert!(
        res.answer.iter().all(|x| x.name == name("www.example.com")),
        "{:?}",
        res.answer
    );
    let t0 = std::time::Instant::now();
    assert!(
        r.resolve(name("www.lame.com"), rtype::A, false)
            .await
            .is_err()
    );
    assert!(t0.elapsed() < Duration::from_secs(3));
}

/// REQ: DNS-012 — 0x20: names go out in mixed case; a server that doesn't echo the case is
/// asked again plainly and still answers.
#[tokio::test]
async fn dns_012_case_randomization() {
    let (mut s, log) = tree(|z| z[2].1.lowercase = true).await;
    s.case_randomization = true;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
    let seen = log.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|(_, n)| n.chars().any(|c| c.is_ascii_uppercase())),
        "some letters went out uppercase: {seen:?}"
    );
}

/// REQ: DNS-012 — 0x20 holds against a spoofed reply: an answer whose letter case differs
/// is not the server's word, so the resolver keeps waiting for one with the case intact
/// instead of asking again plainly (which would let a spoofer who guessed the ID and port
/// win on the retry).
#[tokio::test]
async fn dns_012_case_mismatch_does_not_drop_0x20() {
    let (mut s, log) = tree(|z| z[2].1.spoof = true).await;
    s.case_randomization = true;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(
        addrs(&res),
        vec![IpAddr::from([10, 0, 0, 1])],
        "the server's answer, not the spoofed one"
    );
    let seen = log.lock().unwrap().clone();
    assert_eq!(
        seen.iter().filter(|(ip, _)| *ip == 4).count(),
        1,
        "asked once, never again plainly: {seen:?}"
    );
}

/// REQ: DNS-012, UPS-012 — `answer` returns a full response for the client's query: its
/// ID and question, RA, the records.
#[tokio::test]
async fn dns_012_answer_message() {
    let (s, _) = tree(|_| {}).await;
    let r = Recursor::new(s);
    let mut q = [0u8; 512];
    let len = telltale_proto::build_query(
        &mut q,
        0x1234,
        &name("www.example.com"),
        rtype::A,
        1,
        true,
        None,
    )
    .unwrap();
    let resp = r.answer(&q[..len]).await.unwrap();
    let h = telltale_proto::Header::parse(&resp).unwrap();
    assert_eq!(
        (h.id, h.flags.qr(), h.flags.ra(), h.flags.rd(), h.ancount),
        (0x1234, true, true, true, 1)
    );
    let s = telltale_proto::summarize(&resp).unwrap();
    assert_eq!((s.rcode, s.answers), (rcode::NOERROR, 1));
}

/// REQ: DNS-012 (T9.8) — RFC 8109: the hints are only asked for the root's NS set; its
/// answer (with glue) becomes the root servers from then on.
#[tokio::test]
async fn dns_012_root_priming() {
    let (mut s, log) = tree(|zones| {
        // The real root also answers its own NS set: a.root.com at 127.0.0.2, with glue.
        zones[0].1.records.push(("", rtype::NS, wire("a.root.com")));
        zones[0]
            .1
            .records
            .push(("a.root.com", rtype::A, a([127, 0, 0, 2])));
        // A stand-in "hint" root at .9 with the same data.
        let hint = zones[0].1.clone();
        zones.push((9, hint));
    })
    .await;
    s.roots = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9))];
    s.prime = true;
    let r = Recursor::new(s);
    let res = r
        .resolve(name("www.example.com"), rtype::A, false)
        .await
        .unwrap();
    assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
    let seen = log.lock().unwrap().clone();
    let hint: Vec<&String> = seen
        .iter()
        .filter(|(ip, _)| *ip == 9)
        .map(|(_, n)| n)
        .collect();
    assert_eq!(
        hint,
        vec!["."],
        "the hint saw only the priming query: {seen:?}"
    );
    assert!(
        seen.iter().any(|(ip, n)| *ip == 2 && n == ".com."),
        "{seen:?}"
    );
}

/// REQ: DNS-012 (T9.8) — a server slower than usual is hedged: the next one answers first.
#[tokio::test]
async fn dns_012_hedged_queries() {
    let slow = Arc::new(AtomicU64::new(0));
    let other = Arc::new(AtomicU64::new(5));
    let (slow2, other2) = (Arc::clone(&slow), Arc::clone(&other));
    let (s, _) = tree(move |zones| {
        // example.com has two servers: .4 (made slow later) and .10, a copy.
        let com = &mut zones[1].1;
        com.cuts
            .push(("example.com", "ns2.example.com", Some([127, 0, 0, 10])));
        let mut copy = zones[2].1.clone();
        copy.delay_ms = Some(other2);
        zones[2].1.delay_ms = Some(slow2);
        zones.push((10, copy));
    })
    .await;
    let mut s = s;
    s.server_timeout = Duration::from_millis(1200);
    // One slow lookup with a fresh recursor that has learned both servers.
    let measure = |hedge: bool| {
        let (s, slow) = (s.clone(), Arc::clone(&slow));
        async move {
            // The fake server answers one query at a time: let a slow one finish first.
            tokio::time::sleep(Duration::from_millis(800)).await;
            slow.store(0, Ordering::Relaxed);
            let mut st = s;
            st.hedge = hedge;
            let r = Recursor::new(st);
            // .4 answers at once, .10 after 5 ms, so .4 is tried first.
            for _ in 0..4 {
                r.resolve(name("www.example.com"), rtype::A, false)
                    .await
                    .unwrap();
                r.resolve(name("deep.ent.example.com"), rtype::A, false)
                    .await
                    .unwrap();
            }
            slow.store(700, Ordering::Relaxed);
            let t0 = std::time::Instant::now();
            let res = r
                .resolve(name("www.example.com"), rtype::A, false)
                .await
                .unwrap();
            assert_eq!(addrs(&res), vec![IpAddr::from([10, 0, 0, 1])]);
            t0.elapsed()
        }
    };
    // The hedge goes after 150 ms; without it, the slow server's attempt times out at its
    // 250 ms floor. The best of three runs each, so a busy machine (the whole suite runs in
    // parallel) doesn't decide.
    let (mut hedged, mut plain) = (Duration::MAX, Duration::MAX);
    for _ in 0..3 {
        hedged = hedged.min(measure(true).await);
        plain = plain.min(measure(false).await);
    }
    assert!(plain >= Duration::from_millis(240), "not hedged: {plain:?}");
    assert!(
        hedged + Duration::from_millis(60) < plain,
        "hedged {hedged:?} vs not hedged {plain:?}"
    );
}
