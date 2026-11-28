// REQ: API-004 (issue #63, ADR-175) — a reverse proxy on this machine that `[api] trusted_proxies`
// doesn't list makes every browser look like loopback. `remote()` says so in the log, once in ten
// minutes, and changes nothing else: the address it returns is the same in every case below.
//
// `tracing-subscriber` is not a dependency of this crate, so the log is read by a subscriber of
// about thirty lines. The clock is injected (`ProxyHint::advance`), so no test waits for ten
// minutes or races the real clock.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::http::{Extensions, HeaderMap, HeaderValue};
use tracing::field::{Field, Visit};

use super::{OnBehalfOf, ProxyHint, remote};
use crate::auth::{Auth, Settings};

/// What the test subscriber saw: each event's level and its whole text (message, then fields).
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<(tracing::Level, String)>>>);

impl tracing::Subscriber for Lines {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Text(String);
        impl Visit for Text {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                let _ = if field.name() == "message" {
                    write!(self.0, "{value:?}")
                } else {
                    write!(self.0, " {}={value:?}", field.name())
                };
            }
        }
        let mut text = Text(String::new());
        event.record(&mut text);
        if let Ok(mut v) = self.0.lock() {
            v.push((*event.metadata().level(), text.0));
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Runs `body` with the subscriber installed on this thread; returns its result and what was logged.
fn said<T>(body: impl FnOnce() -> T) -> (T, Vec<(tracing::Level, String)>) {
    let lines = Lines::default();
    let out = tracing::subscriber::with_default(lines.clone(), body);
    let seen = lines.0.lock().map(|v| v.clone()).unwrap_or_default();
    (out, seen)
}

fn auth(trusted: &[(&str, u8)]) -> Auth {
    Auth::new(
        Arc::new(telltale_store::state::State::in_memory().unwrap()),
        Settings {
            trusted_proxies: trusted
                .iter()
                .map(|(a, p)| (a.parse().unwrap(), *p))
                .collect(),
            ..Settings::default()
        },
    )
}

/// A request that arrived on the TCP connection from `peer`.
fn from(peer: &str) -> Extensions {
    let mut e = Extensions::new();
    e.insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 40_000)));
    e
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.insert(*k, HeaderValue::from_str(v).unwrap());
    }
    h
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

const SAYS: &str = "carry a forwarded-address header";
/// What the line for a proxy that sends only `Forwarded` says instead.
const ONLY_FORWARDED: &str = "reads client addresses only from `X-Forwarded-For`";

#[test]
fn api_004_an_unlisted_same_host_proxy_gets_one_hint_for_a_burst_and_another_after_ten_minutes() {
    let a = auth(&[]);
    let h = headers(&[("x-forwarded-for", "203.0.113.9")]);
    let ext = from("127.0.0.1");
    let (answers, lines) = said(|| (0..50).map(|_| remote(&a, &ext, &h)).collect::<Vec<_>>());
    assert!(
        answers.iter().all(|a| *a == ip("127.0.0.1")),
        "the client is still the proxy's address: {answers:?}"
    );
    assert_eq!(lines.len(), 1, "one line for fifty requests: {lines:?}");
    let (level, text) = &lines[0];
    assert_eq!(*level, tracing::Level::INFO);
    for want in [SAYS, "127.0.0.1", "[api] trusted_proxies", "list it"] {
        assert!(text.contains(want), "no `{want}` in: {text}");
    }
    assert!(
        !text.contains("203.0.113.9"),
        "never the client's address from the header: {text}"
    );

    // Nine minutes and fifty seconds on: still the same ten minutes, and quiet.
    a.proxy_hint.advance(Duration::from_secs(590));
    let (answers, lines) = said(|| (0..20).map(|_| remote(&a, &ext, &h)).collect::<Vec<_>>());
    assert!(answers.iter().all(|a| *a == ip("127.0.0.1")));
    assert!(lines.is_empty(), "{lines:?}");
    // Past ten minutes: once more, and then quiet again.
    a.proxy_hint.advance(Duration::from_secs(20));
    let (answers, lines) = said(|| (0..20).map(|_| remote(&a, &ext, &h)).collect::<Vec<_>>());
    assert!(answers.iter().all(|a| *a == ip("127.0.0.1")));
    assert_eq!(lines.len(), 1, "{lines:?}");
}

#[test]
fn api_004_the_hint_is_for_a_loopback_peer_only_and_never_for_a_listed_proxy() {
    // A LAN or public client that sends the header itself is a spoof attempt, not a proxy: no noise.
    for peer in [
        "192.168.1.5",
        "10.0.0.1",
        "203.0.113.9",
        "fe80::1",
        "2001:db8::5",
    ] {
        let a = auth(&[]);
        let h = headers(&[
            ("x-forwarded-for", "127.0.0.1"),
            ("forwarded", "for=127.0.0.1"),
        ]);
        let (got, lines) = said(|| remote(&a, &from(peer), &h));
        assert_eq!(got, ip(peer), "the peer is the client: {peer}");
        assert!(lines.is_empty(), "{peer}: {lines:?}");
    }

    // A proxy on this machine that is listed: its client is read from the header, and nothing is said.
    let a = auth(&[("127.0.0.1", 32)]);
    let h = headers(&[("x-forwarded-for", "203.0.113.9")]);
    let (got, lines) = said(|| remote(&a, &from("127.0.0.1"), &h));
    assert_eq!(got, ip("203.0.113.9"), "the client behind the proxy");
    assert!(lines.is_empty(), "{lines:?}");

    // An ingress's network that doesn't include loopback doesn't make loopback a proxy.
    let a = auth(&[("10.42.0.0", 16)]);
    let h = headers(&[("x-forwarded-for", "203.0.113.9")]);
    let (got, lines) = said(|| remote(&a, &from("127.0.0.1"), &h));
    assert_eq!(got, ip("127.0.0.1"));
    assert_eq!(
        lines.len(),
        1,
        "that is the case the hint is for: {lines:?}"
    );

    // A request made in-process for a client (the MCP server) has its client's address already.
    let a = auth(&[]);
    let mut ext = from("127.0.0.1");
    ext.insert(OnBehalfOf(ip("198.51.100.4")));
    let (got, lines) = said(|| remote(&a, &ext, &h));
    assert_eq!(got, ip("198.51.100.4"));
    assert!(lines.is_empty(), "{lines:?}");
}

#[test]
fn api_004_the_hint_needs_a_forwarded_address_header_and_counts_every_loopback_form() {
    // No header, or one that doesn't name a client: nothing to hint about (a TLS terminator on this
    // machine sends X-Forwarded-Proto and is not a mistake).
    for pairs in [
        vec![],
        vec![("x-forwarded-proto", "https")],
        vec![("x-real-ip", "203.0.113.9")],
        vec![("x-forwarded-host", "dns.example")],
    ] {
        let a = auth(&[]);
        let (got, lines) = said(|| remote(&a, &from("127.0.0.1"), &headers(&pairs)));
        assert_eq!(got, ip("127.0.0.1"));
        assert!(lines.is_empty(), "{pairs:?}: {lines:?}");
    }
    // `X-Forwarded-For`, from any form of loopback, gets one line (the one that says to list the
    // proxy: listing it makes this node read the client from that header).
    for peer in ["127.0.0.1", "127.0.0.5", "::1", "::ffff:127.0.0.1"] {
        let a = auth(&[]);
        let pairs = [("x-forwarded-for", "203.0.113.9")];
        let (got, lines) = said(|| remote(&a, &from(peer), &headers(&pairs)));
        assert_eq!(got, ip(peer), "{peer}: still the peer");
        assert_eq!(lines.len(), 1, "{peer} {pairs:?}: {lines:?}");
        assert!(lines[0].1.contains(SAYS), "{peer}: {lines:?}");
        assert!(!lines[0].1.contains(ONLY_FORWARDED), "{peer}: {lines:?}");
    }
    // The standard `Forwarded` header alone also gets one line, but not that advice: see below.
    let a = auth(&[]);
    let pairs = [("forwarded", "for=203.0.113.9;proto=https")];
    let (got, lines) = said(|| remote(&a, &from("127.0.0.1"), &headers(&pairs)));
    assert_eq!(got, ip("127.0.0.1"), "still the peer");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].1.contains(ONLY_FORWARDED), "{lines:?}");
}

/// F1 of the final review: this node reads a listed proxy's client only from `X-Forwarded-For`
/// (`Forwarded` is never parsed). A proxy that sends only `Forwarded` must not be told to "list
/// it": that would stop the hint and leave every client looking like the proxy, with the
/// break-glass list as open as before. It is told to send `X-Forwarded-For` first.
#[test]
fn api_004_a_proxy_that_sends_only_forwarded_is_told_to_send_x_forwarded_for() {
    let a = auth(&[]);
    let h = headers(&[(
        "forwarded",
        "for=evil-marker-fwd;by=198.51.100.7;proto=https",
    )]);
    let (got, lines) = said(|| remote(&a, &from("127.0.0.1"), &h));
    assert_eq!(
        got,
        ip("127.0.0.1"),
        "remote() is unchanged: the proxy's address"
    );
    assert_eq!(lines.len(), 1, "{lines:?}");
    let (level, text) = &lines[0];
    assert_eq!(*level, tracing::Level::INFO);
    for want in [
        "127.0.0.1",
        "`Forwarded`",
        ONLY_FORWARDED,
        "make the proxy send `X-Forwarded-For`",
        "[api] trusted_proxies",
    ] {
        assert!(text.contains(want), "no `{want}` in: {text}");
    }
    assert!(
        !text.contains(SAYS),
        "not the line that says listing the proxy is enough: {text}"
    );
    for never in ["evil-marker", "198.51.100.7"] {
        assert!(!text.contains(never), "`{never}` is in: {text}");
    }

    // Both headers: the proxy does send `X-Forwarded-For`, so it is the ordinary line.
    let a = auth(&[]);
    let h = headers(&[
        ("x-forwarded-for", "203.0.113.9"),
        ("forwarded", "for=203.0.113.9"),
    ]);
    let (got, lines) = said(|| remote(&a, &from("127.0.0.1"), &h));
    assert_eq!(got, ip("127.0.0.1"));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].1.contains(SAYS), "{lines:?}");
    assert!(!lines[0].1.contains(ONLY_FORWARDED), "{lines:?}");

    // Both lines share one limiter: whichever comes first in ten minutes is the only one.
    let a = auth(&[]);
    let only = headers(&[("forwarded", "for=203.0.113.9")]);
    let xff = headers(&[("x-forwarded-for", "203.0.113.9")]);
    let ((), lines) = said(|| {
        remote(&a, &from("127.0.0.1"), &only);
        remote(&a, &from("127.0.0.1"), &xff);
    });
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].1.contains(ONLY_FORWARDED), "{lines:?}");
    a.proxy_hint.advance(Duration::from_secs(601));
    let (_, lines) = said(|| remote(&a, &from("127.0.0.1"), &xff));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].1.contains(SAYS), "{lines:?}");

    // Listing a proxy that sends only `Forwarded` silences the hint and reveals no client: the
    // address is still the proxy's. That is why the line above says to send `X-Forwarded-For` first.
    let a = auth(&[("127.0.0.1", 32)]);
    let h = headers(&[("forwarded", "for=203.0.113.9")]);
    let (got, lines) = said(|| remote(&a, &from("127.0.0.1"), &h));
    assert_eq!(
        got,
        ip("127.0.0.1"),
        "a listed proxy's `Forwarded` header is not read"
    );
    assert!(lines.is_empty(), "{lines:?}");
}

#[test]
fn api_004_the_hint_never_contains_what_the_header_said() {
    // The header is whatever the sender wrote, so it is never copied into the log: not the value,
    // not an address parsed from it, and no control character gets in.
    let a = auth(&[]);
    let h = headers(&[
        (
            "x-forwarded-for",
            "evil-marker-xff, 203.0.113.9, 2001:db8::bad",
        ),
        (
            "forwarded",
            "for=\"evil-marker-forwarded\";by=198.51.100.77",
        ),
    ]);
    let (_, lines) = said(|| remote(&a, &from("127.0.0.1"), &h));
    assert_eq!(lines.len(), 1, "{lines:?}");
    let text = &lines[0].1;
    for never in [
        "evil-marker",
        "203.0.113.9",
        "2001:db8::bad",
        "198.51.100.77",
    ] {
        assert!(!text.contains(never), "`{never}` is in: {text}");
    }
    assert!(
        text.chars().all(|c| !c.is_control()),
        "one clean line: {text:?}"
    );
}

// ---- the walk from the right (API-004, ADR-034)

/// Headers whose `X-Forwarded-For` field lines are `lines`, in order.
fn forwarded(lines: &[&[u8]]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for l in lines {
        h.append("x-forwarded-for", HeaderValue::from_bytes(l).unwrap());
    }
    h
}

/// The field lines as text, for a failure message.
fn shown(lines: &[&[u8]]) -> Vec<String> {
    lines
        .iter()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect()
}

/// REQ: API-004 (ADR-034) — the walk from the right stops at the first entry that isn't a bare
/// IPv4 or IPv6 address, and the client is then the peer, as with no header. It never goes on to
/// an entry further left: the client wrote those.
#[test]
fn api_004_xff_unparsable_entry_is_not_skipped() {
    let a = auth(&[("10.0.0.1", 32), ("10.0.0.2", 32)]);
    let peer = "10.0.0.1";
    let mut wrong = Vec::new();
    for (lines, what) in [
        (
            &[&b"192.168.1.5, 203.0.113.9:4711"[..]][..],
            "an address and a port",
        ),
        (
            &[&b"192.168.1.5, [2001:db8::1]"[..]][..],
            "a bracketed IPv6 address",
        ),
        (
            &[&b"192.168.1.5, [2001:db8::1]:443"[..]][..],
            "brackets and a port",
        ),
        (&[&b"192.168.1.5, unknown"[..]][..], "a token"),
        (
            &[&b"192.168.1.5, 203.0.113.9:4711, 10.0.0.2"[..]][..],
            "behind a listed proxy",
        ),
        (&[&b"192.168.1.5, , 10.0.0.2"[..]][..], "an empty entry"),
        (&[&b"192.168.1.5,"[..]][..], "an empty last entry"),
        (
            &[&b"192.168.1.5"[..], &b"203.0.113.9:4711"[..]][..],
            "on the last field line",
        ),
        (
            &[&b"192.168.1.5"[..], &b"\xfe"[..]][..],
            "a last field line that isn't text",
        ),
        (
            &[&b"192.168.1.5, \xfe, 10.0.0.2"[..]][..],
            "an entry that isn't text, behind a listed proxy",
        ),
        (
            &[&b"192.168.1.5, 10.0.0.2:80"[..]][..],
            "a listed proxy with a port",
        ),
        (&[&b"192.168.1.5, fe80::1%eth0"[..]][..], "a zone id"),
        (&[&b"192.168.1.5, 010.0.0.2"[..]][..], "leading zeros"),
    ] {
        let got = remote(&a, &from(peer), &forwarded(lines));
        if got != ip(peer) {
            wrong.push(format!("{what}: {:?} gave {got}", shown(lines)));
        }
    }
    assert!(
        wrong.is_empty(),
        "the peer, {peer}, every time:\n{}",
        wrong.join("\n")
    );
}

/// REQ: API-004 (ADR-034) — what every well-formed header answered before the walk stopped at an
/// unusable entry, and still answers.
#[test]
fn api_004_xff_well_formed_headers_keep_their_answers() {
    let a = auth(&[("10.0.0.1", 32), ("10.0.0.2", 32), ("2001:db8:ffff::", 48)]);
    for (peer, lines, want) in [
        ("10.0.0.1", &[&b"192.168.1.5"[..]][..], "192.168.1.5"),
        (
            "10.0.0.1",
            &[&b"192.168.1.5, 10.0.0.2"[..]][..],
            "192.168.1.5",
        ),
        (
            "10.0.0.1",
            &[&b"127.0.0.1, 192.168.1.5, 10.0.0.2, 10.0.0.1"[..]][..],
            "192.168.1.5",
        ),
        ("10.0.0.1", &[&b"10.0.0.2, 10.0.0.1"[..]][..], "10.0.0.1"),
        ("192.168.1.50", &[&b"127.0.0.1"[..]][..], "192.168.1.50"),
        (
            "192.168.1.50",
            &[&b"203.0.113.9:4711"[..]][..],
            "192.168.1.50",
        ),
        ("10.0.0.1", &[][..], "10.0.0.1"),
        ("10.0.0.1", &[&b""[..]][..], "10.0.0.1"),
        (
            "2001:db8:ffff::1",
            &[&b"2001:db8::5"[..]][..],
            "2001:db8::5",
        ),
        (
            "10.0.0.1",
            &[&b"2001:db8::5, 2001:db8:ffff::9"[..]][..],
            "2001:db8::5",
        ),
        (
            "10.0.0.1",
            &[&b"  192.168.1.5  ,\t10.0.0.2 "[..]][..],
            "192.168.1.5",
        ),
        (
            "10.0.0.1",
            &[&b"192.168.1.5"[..], &b"10.0.0.2"[..]][..],
            "192.168.1.5",
        ),
        (
            "10.0.0.1",
            &[&b"127.0.0.1"[..], &b"192.168.1.5, 10.0.0.2"[..]][..],
            "192.168.1.5",
        ),
        // A listed proxy written as an IPv4-mapped address is still a listed proxy.
        (
            "10.0.0.1",
            &[&b"192.168.1.5, ::ffff:10.0.0.2"[..]][..],
            "192.168.1.5",
        ),
        // Whatever is left of the selected entry is never read.
        (
            "10.0.0.1",
            &[&b"unknown, 203.0.113.9:1, 192.168.1.5"[..]][..],
            "192.168.1.5",
        ),
    ] {
        let got = remote(&a, &from(peer), &forwarded(lines));
        assert_eq!(got, ip(want), "from {peer}: {:?}", shown(lines));
    }
}

/// REQ: API-004 (ADR-034) — the rule is per entry: bytes left of the entry that decides never
/// matter, even in the same field line (a proxy that appends its client to the incoming header
/// writes one line), and whatever they are, text or not.
#[test]
fn api_004_xff_bytes_left_of_the_deciding_entry_never_matter() {
    let a = auth(&[("10.0.0.1", 32), ("10.0.0.2", 32)]);
    let peer = "10.0.0.1";
    let mut wrong = Vec::new();
    for (lines, want) in [
        (&[&b"\xfe, 203.0.113.9"[..]][..], "203.0.113.9"),
        (
            &[&b"\xfe\xff, 192.168.1.5, 10.0.0.2"[..]][..],
            "192.168.1.5",
        ),
        (&[&b"caf\xc3\xa9, 203.0.113.9"[..]][..], "203.0.113.9"),
        (&[&b"\xfe"[..], &b"203.0.113.9"[..]][..], "203.0.113.9"),
        (&[&b"\xfe, 10.0.0.2"[..]][..], peer),
    ] {
        let got = remote(&a, &from(peer), &forwarded(lines));
        if got != ip(want) {
            wrong.push(format!("{:?} gave {got}, not {want}", shown(lines)));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The walk as it was before ADR-034's amendment of 2026-11-27: the oracle for
/// `api_004_xff_walk_matches_the_old_walk_for_bare_entries`.
fn old_remote(a: &Auth, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let trusted = |ip: IpAddr| {
        a.settings()
            .trusted_proxies
            .iter()
            .any(|(n, l)| crate::auth::in_network(ip, *n, *l))
    };
    if !trusted(peer) {
        return peer;
    }
    headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .find(|ip| !trusted(*ip))
        .unwrap_or(peer)
}

/// REQ: API-004 (ADR-034) — for headers made only of bare addresses (any number of field lines
/// and entries, spaces and tabs around them), the walk answers exactly what the old one did.
/// Random lists from a small pool, from a fixed seed: the same cases on every run.
#[test]
fn api_004_xff_walk_matches_the_old_walk_for_bare_entries() {
    const POOL: [&str; 10] = [
        "10.0.0.1",
        "10.0.0.2",
        "192.168.1.5",
        "203.0.113.9",
        "127.0.0.1",
        "2001:db8::5",
        "2001:db8:ffff::9",
        "::ffff:10.0.0.2",
        "::ffff:192.168.1.5",
        "::1",
    ];
    const PEERS: [&str; 4] = ["10.0.0.1", "10.0.0.2", "2001:db8:ffff::1", "192.168.1.50"];
    const SPACE: [&str; 4] = ["", " ", "  ", "\t"];
    let a = auth(&[("10.0.0.1", 32), ("10.0.0.2", 32), ("2001:db8:ffff::", 48)]);
    // xorshift64, fixed seed.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = |n: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        usize::try_from(state % u64::try_from(n).unwrap()).unwrap()
    };
    for case in 0..5000 {
        let peer: IpAddr = PEERS[next(PEERS.len())].parse().unwrap();
        let mut lines = Vec::new();
        for _ in 0..next(4) {
            let entries: Vec<String> = (0..=next(5))
                .map(|_| {
                    let (l, r) = (SPACE[next(SPACE.len())], SPACE[next(SPACE.len())]);
                    format!("{l}{}{r}", POOL[next(POOL.len())])
                })
                .collect();
            lines.push(entries.join(","));
        }
        let mut h = HeaderMap::new();
        for l in &lines {
            h.append("x-forwarded-for", HeaderValue::from_str(l).unwrap());
        }
        let mut ext = Extensions::new();
        ext.insert(ConnectInfo(SocketAddr::new(peer, 40_000)));
        assert_eq!(
            remote(&a, &ext, &h),
            old_remote(&a, peer, &h),
            "case {case}: from {peer}: {lines:?}"
        );
    }
}

#[test]
fn api_004_the_hint_is_due_once_per_ten_minutes_whatever_the_number_of_threads() {
    let hint = ProxyHint::new();
    assert!(hint.due(0), "the first time");
    assert!(!hint.due(1));
    assert!(!hint.due(599_999), "a millisecond short of ten minutes");
    assert!(hint.due(600_000), "ten minutes after the line");
    assert!(!hint.due(600_001));
    assert!(!hint.due(1_199_999));
    assert!(hint.due(1_200_000));

    // Many requests at the same instant: exactly one of them says it.
    let hint = ProxyHint::new();
    let gate = std::sync::Barrier::new(16);
    let told = std::thread::scope(|scope| {
        let all: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    gate.wait();
                    hint.due(5_000_000)
                })
            })
            .collect();
        all.into_iter()
            .map(|h| h.join().is_ok_and(|due| due))
            .filter(|due| *due)
            .count()
    });
    assert_eq!(told, 1);
}
