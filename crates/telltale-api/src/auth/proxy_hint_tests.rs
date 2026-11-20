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
