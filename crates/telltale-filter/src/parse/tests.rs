use super::*;

fn one(line: &str) -> String {
    one_with(line, ListOptions::default())
}

fn one_with(line: &str, opts: ListOptions) -> String {
    let mut out = Vec::new();
    match parse_line(line, opts, &mut out) {
        LineKind::Rules(_) => out
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" + "),
        other => format!("{other:?}"),
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one table row per case
fn flt_001_line_table() {
    let cases = [
        // blank, comments, headers
        ("", "Blank"),
        ("   \t", "Blank"),
        ("# hosts comment", "Comment"),
        ("! Title: AdBlock list", "Comment"),
        ("[Adblock Plus 2.0]", "Comment"),
        // hosts
        ("0.0.0.0 ads.example.com", "block subtree ads.example.com"),
        (
            "127.0.0.1\tTracker.Example.NET.",
            "block subtree tracker.example.net",
        ),
        (
            "0.0.0.0 a.example.com b.example.com # two",
            "block subtree a.example.com + block subtree b.example.com",
        ),
        ("::1 ip6-localhost ip6-loopback", "Ignored"),
        ("127.0.0.1 localhost", "Ignored"),
        ("0.0.0.0 0.0.0.0", "Ignored"),
        ("0.0.0.0", "Unsupported(\"IP address without a name\")"),
        (
            "0.0.0.0 bad_name!.com",
            "Invalid(\"`bad_name!.com`: invalid character in name\")",
        ),
        // plain + wildcard
        ("ads.example.com", "block subtree ads.example.com"),
        ("ads.example.com # inline", "block subtree ads.example.com"),
        ("*.example.com", "block subdomains example.com"),
        (".example.com", "block subdomains example.com"),
        (".example.com^", "block subdomains example.com"),
        ("..example.com", "Invalid(\"empty label\")"),
        (
            "ads*.example.com",
            "Unsupported(\"wildcard inside a name\")",
        ),
        ("bücher.example", "block subtree xn--bcher-kva.example"),
        ("1.2.3.4", "Unsupported(\"IP address without a name\")"),
        (
            "||1.2.3.4^",
            "Unsupported(\"IP address rule (response IP filtering)\")",
        ),
        ("two words", "Invalid(\"unexpected whitespace\")"),
        // AdBlock / AdGuard DNS
        ("||ads.example.com^", "block subtree ads.example.com"),
        ("||ads.example.com", "block subtree ads.example.com"),
        ("||ads.example.com^|", "block subtree ads.example.com"),
        ("|ads.example.com^", "block exact ads.example.com"),
        ("ads.example.com^", "block subtree ads.example.com"),
        ("@@||good.example.com^", "allow subtree good.example.com"),
        (
            "@@|good.example.com^$important",
            "allow exact good.example.com $important",
        ),
        ("||*.example.com^", "block subdomains example.com"),
        ("||xyz^", "block subtree xyz"),
        (
            "||ads.example.com^$important",
            "block subtree ads.example.com $important",
        ),
        (
            "||ads.example.com^$badfilter",
            "block subtree ads.example.com $badfilter",
        ),
        (
            "||ads.example.com^$dnstype=AAAA|~A",
            "block subtree ads.example.com $dnstype=AAAA|~A",
        ),
        (
            "||example.com^$denyallow=cdn.example.com",
            "block subtree example.com $denyallow=cdn.example.com",
        ),
        (
            "@@||example.com^$denyallow=a.com",
            "Invalid(\"$denyallow only applies to blocking rules\")",
        ),
        (
            "||ads.example.com^$client='Frank laptop'",
            "block subtree ads.example.com $client='Frank laptop'",
        ),
        (
            "||ads.example.com^$client=192.168.1.0/24|~192.168.1.5",
            "block subtree ads.example.com $client='192.168.1.0/24'|~'192.168.1.5'",
        ),
        (
            "||ads.example.com^$dnsrewrite=NOERROR;A;1.2.3.4",
            "block subtree ads.example.com $dnsrewrite=NOERROR;A;1.2.3.4",
        ),
        (
            "||ads.example.com^$third-party",
            "Unsupported(\"modifier $third-party is not supported\")",
        ),
        (
            "||ads.example.com^$ctag=device_tv",
            "Unsupported(\"modifier $ctag is not supported\")",
        ),
        (
            "||ads.example.com^$dnstype=NOPE",
            "Invalid(\"unknown query type `NOPE`\")",
        ),
        (
            "||ads.example.com/banner.js",
            "Unsupported(\"URL rule (DNS filtering sees names only)\")",
        ),
        (
            "||ads*.example.com^",
            "Unsupported(\"wildcard inside a name\")",
        ),
        ("||^", "Invalid(\"rule without a name\")"),
        (
            "example.com##.ad-banner",
            "Unsupported(\"cosmetic or HTML filtering rule\")",
        ),
        (
            "example.com#@#.ad",
            "Unsupported(\"cosmetic or HTML filtering rule\")",
        ),
        (
            "example.com$$script",
            "Unsupported(\"cosmetic or HTML filtering rule\")",
        ),
        ("/^ad[0-9]+\\./", "block regex /^ad[0-9]+\\./"),
        (
            "/^ad[0-9]+\\./$dnstype=A",
            "block regex /^ad[0-9]+\\./ $dnstype=A",
        ),
        ("@@/^safe\\./", "allow regex /^safe\\./"),
        ("/ads/banner", "Unsupported(\"URL path rule\")"),
        ("/banner/ads/", "Unsupported(\"URL path rule\")"),
        ("fe80::1%lo0 localhost", "Ignored"),
        (
            "fe80::1%lo0 zoned.example.com",
            "block subtree zoned.example.com",
        ),
        // Pi-hole regex
        (
            "(^|\\.)doubleclick\\.net$",
            "block regex /(^|\\.)doubleclick\\.net$/",
        ),
        (
            "^ad[0-9]*\\.example\\.com$;querytype=A,AAAA",
            "block regex /^ad[0-9]*\\.example\\.com$/ $dnstype=A|AAAA",
        ),
        (
            "^tracker\\.;querytype=!HTTPS",
            "block regex /^tracker\\./ $dnstype=~HTTPS",
        ),
        (
            "^allowed\\.example\\.com$;invert",
            "block regex-invert /^allowed\\.example\\.com$/",
        ),
        (
            "^a\\.;reply=nxdomain",
            "Unsupported(\"Pi-hole regex option `;reply` is not supported\")",
        ),
        (
            "^(a)\\1$",
            "Invalid(\"regex: backreferences are not supported\")",
        ),
        (
            "^(?=ads)",
            "Invalid(\"regex: look-around, including look-ahead and look-behind, is not supported\")",
        ),
        ("^ad(s", "Invalid(\"regex: unclosed group\")"),
        (
            "^x;querytype=BOGUS",
            "Invalid(\"unknown query type `BOGUS`\")",
        ),
    ];
    let mut failures = Vec::new();
    for (line, want) in cases {
        let got = one(line);
        if got != want {
            failures.push(format!("{line:?}\n   want {want}\n    got {got}"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn flt_002_list_options_set_action_and_scope() {
    let allow_exact = ListOptions {
        kind: ListKind::Allow,
        match_mode: ListMatch::Exact,
    };
    assert_eq!(
        one_with("good.example.com", allow_exact),
        "allow exact good.example.com"
    );
    assert_eq!(
        one_with("0.0.0.0 good.example.com", allow_exact),
        "allow exact good.example.com"
    );
    // Explicit AdBlock anchors win over the list's match mode; the list's kind applies.
    assert_eq!(
        one_with("||good.example.com^", allow_exact),
        "allow subtree good.example.com"
    );
    assert_eq!(
        one_with("*.example.com", allow_exact),
        "allow subdomains example.com"
    );
}

#[test]
fn flt_001_list_stats_and_line_numbers() {
    let data = b"\xEF\xBB\xBF# header\r\n\r\n||a.example.com^\r\n0.0.0.0 b.example.com c.example.com\nexample.com##.ad\nnot valid!\n127.0.0.1 localhost";
    let mut rules = Vec::new();
    let stats = parse_list(data, ListOptions::default(), |line, r| {
        rules.push((line, r.to_string()));
    });
    assert_eq!(
        rules,
        vec![
            (3, "block subtree a.example.com".to_owned()),
            (4, "block subtree b.example.com".to_owned()),
            (4, "block subtree c.example.com".to_owned()),
        ]
    );
    assert_eq!(stats.lines, 7);
    assert_eq!((stats.blank, stats.comments, stats.ignored), (1, 1, 1));
    assert_eq!((stats.rules, stats.unsupported, stats.invalid), (3, 1, 1));
    assert_eq!(stats.samples.len(), 2);
    assert_eq!(
        (stats.samples[1].line, stats.samples[1].unsupported),
        (6, false)
    );

    assert_eq!(parse_list(b"", ListOptions::default(), |_, _| {}).lines, 0);
    assert_eq!(
        parse_list(b"a.com", ListOptions::default(), |_, _| {}).rules,
        1
    );
    assert_eq!(
        parse_list(b"a.com\n", ListOptions::default(), |_, _| {}).lines,
        1
    );
    assert_eq!(
        parse_list(b"a.com\n\n", ListOptions::default(), |_, _| {}).lines,
        2
    );
}

#[test]
fn flt_001_never_panics_on_garbage() {
    // Cheap fuzz: every byte value and some nasty shapes.
    let mut nasty: Vec<Vec<u8>> = (0u8..=255)
        .map(|b| vec![b, b'.', b'c', b'o', b'm'])
        .collect();
    for s in [
        "||",
        "|",
        "@@",
        "@@@@",
        "/",
        "//",
        "/$",
        "$",
        "^",
        "^^",
        "||$",
        "*.",
        "*",
        ";invert",
        ";querytype=",
        "0.0.0.0 #",
        "\u{feff}",
        "||a^$client=''",
        "||a^$client=\"",
        "||a^$dnstype=|",
        "x;=;",
    ] {
        nasty.push(s.as_bytes().to_vec());
    }
    for line in nasty {
        let _ = parse_list(&line, ListOptions::default(), |_, _| {});
    }
}
