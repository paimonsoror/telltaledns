// REQ: moved out of `auth_setup.rs` so the test code is a file of its own (CodeQL ignores test paths).
use super::*;

fn cfg(dir: &Path) -> Config {
    let mut c = Config::default();
    c.node.data_dir = telltale_config::SafeString::new(dir.to_string_lossy()).unwrap();
    c
}

// REQ: API-003 — the setup token survives restarts until the first admin exists.
#[test]
fn api_003_setup_token_is_kept_private_and_reused_across_restarts() {
    let dir = std::env::temp_dir().join(format!("tt-auth-{}", crypto::random_id()));
    let c = cfg(&dir);
    let a = open(&c).unwrap();
    let t1 = a.setup_token().unwrap().unwrap();
    let file = dir.join(SETUP_TOKEN_FILE);
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&file).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o600);
    drop(a);
    let a = open(&c).unwrap();
    assert_eq!(
        a.setup_token().unwrap().as_deref(),
        Some(t1.as_str()),
        "same token after a restart"
    );
    a.setup(&t1, "root", "correct horse battery", now())
        .unwrap();
    assert!(!file.exists());
    drop(a);
    let a = open(&c).unwrap();
    assert!(!a.setup_required().unwrap());
    assert!(!file.exists(), "no new token once set up");
    let _ = std::fs::remove_dir_all(&dir);
}

// REQ: API-002, AGT-003 (ADR-181) — security F5: the request key is made once, private, in the
// data directory's secrets/ folder, and the same after a restart (so a retry still replays); a
// file that isn't a key is left alone and is an error.
#[test]
fn api_002_the_request_key_is_private_and_kept_across_restarts() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = temp_dir();
    let c = cfg(&dir);
    let a = open(&c).unwrap();
    let file = dir.join(REQUEST_KEY_FILE);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(file.parent().unwrap()), 0o700);
    let first = a.request_digest("the-key");
    assert_ne!(
        first,
        blake3::hash(b"the-key").to_hex().to_string(),
        "keyed, not a plain hash"
    );
    drop(a);
    let a = open(&c).unwrap();
    assert_eq!(
        a.request_digest("the-key"),
        first,
        "the same key after a restart"
    );
    drop(a);
    std::fs::write(&file, "not a key").unwrap();
    let e = request_key(&dir).unwrap_err().to_string();
    assert!(e.contains("not a request key"), "{e}");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "not a key",
        "left alone"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// REQ: API-002, AGT-003 (ADR-181) — review round 2, security N6: the request key appears whole or
// not at all. Starts racing to make it (a server and a CLI, say) all get the same key, none reads
// a file still being written, and no temporary file is left.
#[test]
fn api_002_the_request_key_is_made_whole_or_not_at_all() {
    for round in 0..30 {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let keys: Vec<_> = std::thread::scope(|s| {
            let racers: Vec<_> = (0..8).map(|_| s.spawn(|| request_key(&dir))).collect();
            racers.into_iter().map(|r| r.join().unwrap()).collect()
        });
        let first = keys[0].as_ref().map_err(ToString::to_string).cloned();
        for k in &keys {
            assert_eq!(
                k.as_ref().map_err(ToString::to_string).cloned(),
                first,
                "round {round}"
            );
        }
        assert!(first.is_ok(), "round {round}: {first:?}");
        let left: Vec<_> = std::fs::read_dir(dir.join("secrets"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec![".request-key".to_owned()], "round {round}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// What a test subscriber saw: each event's level and message, in order.
#[derive(Clone, Default)]
struct Seen(Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Seen {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut m = Message(String::new());
        event.record(&mut m);
        if let Ok(mut v) = self.0.lock() {
            v.push((*event.metadata().level(), m.0));
        }
    }
}

/// Runs `open(c)` and returns the lines about password sign-in that it logged (the start-up
/// notice is the only one that says "password sign-in"), plus whether it logged that the
/// provider could not be set up.
fn start_up(c: &Config) -> (Vec<(tracing::Level, String)>, bool) {
    use tracing_subscriber::layer::SubscriberExt as _;
    let seen = Seen::default();
    let sub = tracing_subscriber::registry().with(seen.clone());
    let auth = tracing::subscriber::with_default(sub, || open(c).unwrap());
    drop(auth);
    let all = seen.0.lock().unwrap().clone();
    let provider_failed = all.iter().any(|(_, l)| l.contains("OIDC sign-in disabled"));
    let notices = all
        .into_iter()
        .filter(|(_, l)| l.contains("password sign-in"))
        .collect();
    (notices, provider_failed)
}

fn cidrs(list: &[&str]) -> Vec<Cidr> {
    list.iter().map(|s| Cidr::parse(s).unwrap()).collect()
}

/// A provider that sets up (nothing is contacted until someone signs in), or one whose secret
/// file is missing.
fn provider(secret_file: Option<&str>) -> telltale_config::OidcProvider {
    let s = |v: &str| telltale_config::SafeString::new(v).unwrap();
    telltale_config::OidcProvider {
        id: s("kc"),
        name: s("Keycloak"),
        issuer: s("https://auth.example.com/realms/home"),
        client_id: s("telltale"),
        client_secret: secret_file.is_none().then(|| s("s3cret")),
        client_secret_file: secret_file.map(s),
        scopes: vec![s("openid")],
        username_claim: s("preferred_username"),
        groups_claim: s("groups"),
        role: Vec::new(),
        default_role: None,
        require_verified_email: false,
    }
}

/// A config in `dir` with local sign-in off and these break-glass networks, and a provider.
fn break_glass(dir: &Path, networks: Vec<Cidr>, secret_file: Option<&str>) -> Config {
    let mut c = cfg(dir);
    c.auth.oidc.disable_local_login = true;
    c.auth.oidc.allowed_admin_networks = networks;
    c.auth.oidc.provider = vec![provider(secret_file)];
    c
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(format!("tt-auth-{}", crypto::random_id()))
}

// REQ: API-004 (issue #63, ADR-175) — with the flag on and a list that covers whole networks (a
// range of more than one host, not only this machine), password sign-in is still open to everyone
// on them, so start-up warns (it used to be an INFO line that read "password sign-in is off"), and
// says which networks and that it is the default.
#[test]
fn api_004_start_up_warns_when_break_glass_reaches_beyond_loopback() {
    let default = Config::default().auth.oidc.allowed_admin_networks;
    for (what, networks) in [
        ("the default list", default.clone()),
        (
            "loopback and one LAN range",
            cidrs(&["127.0.0.0/8", "192.168.1.0/24"]),
        ),
        (
            "a LAN host and a LAN range",
            cidrs(&["192.168.1.5/32", "10.0.0.0/8"]),
        ),
        ("two hosts and no more (a /31)", cidrs(&["192.168.1.10/31"])),
        ("every address", cidrs(&["0.0.0.0/0"])),
    ] {
        let dir = temp_dir();
        let (lines, _) = start_up(&break_glass(&dir, networks.clone(), None));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(lines.len(), 1, "{what}: {lines:?}");
        let (level, line) = &lines[0];
        assert_eq!(*level, tracing::Level::WARN, "{what}: {line}");
        for n in &networks {
            assert!(line.contains(&n.to_string()), "{what}: {line} names {n}");
        }
        assert!(line.contains("still open"), "{what}: {line}");
        assert!(line.contains("allowed_admin_networks"), "{what}: {line}");
        assert_eq!(
            line.contains("default"),
            networks == default,
            "{what}: only the default list is called that: {line}"
        );
        assert!(
            line.contains("[]"),
            "{what}: says how to turn it off: {line}"
        );
    }
}

// REQ: API-004 (issue #63) — a list that stays on this machine is only information, and the line
// says so; behind a proxy on this host it can't know, so it points at `trusted_proxies`.
#[test]
fn api_004_start_up_is_quiet_about_a_loopback_only_list() {
    for networks in [
        cidrs(&["127.0.0.0/8", "::1/128"]),
        cidrs(&["127.0.0.1/32"]),
        cidrs(&["::1/128"]),
    ] {
        let dir = temp_dir();
        let (lines, _) = start_up(&break_glass(&dir, networks.clone(), None));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(lines.len(), 1, "{lines:?}");
        let (level, line) = &lines[0];
        assert_eq!(*level, tracing::Level::INFO, "{networks:?}: {line}");
        assert!(line.contains("restricted to loopback"), "{line}");
        assert!(
            line.contains("trusted_proxies"),
            "a proxy on this host would make every browser look like loopback: {line}"
        );
    }
    // With the proxy listed there is nothing to add.
    let dir = temp_dir();
    let mut c = break_glass(&dir, cidrs(&["127.0.0.0/8"]), None);
    c.api.trusted_proxies = cidrs(&["127.0.0.1/32"]);
    let (lines, _) = start_up(&c);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].0, tracing::Level::INFO);
    assert!(lines[0].1.contains("restricted to loopback"), "{lines:?}");
    assert!(!lines[0].1.contains("trusted_proxies"), "{lines:?}");
}

// REQ: API-004 (ADR-175) — a list of single hosts (/32, /128) names the machines you manage from,
// which is what the docs recommend, so it is information ("restricted to N hosts"), not the
// warning for a list that opens password sign-in to whole networks. Hosts beside loopback count
// as hosts. A single host from a range (a /31) or any network is not.
#[test]
fn api_004_a_list_of_single_hosts_is_information() {
    for (what, networks, says) in [
        (
            "one workstation",
            cidrs(&["192.168.1.10/32"]),
            "restricted to 1 host (",
        ),
        (
            "two workstations",
            cidrs(&["192.168.1.10/32", "192.168.1.11/32"]),
            "restricted to 2 hosts (",
        ),
        (
            "an IPv6 workstation",
            cidrs(&["fd00::5/128"]),
            "restricted to 1 host (",
        ),
        (
            "an IPv4 and an IPv6 workstation",
            cidrs(&["192.168.1.10/32", "fd00::5/128"]),
            "restricted to 2 hosts (",
        ),
        (
            "loopback hosts and a workstation",
            cidrs(&["127.0.0.1/32", "::1/128", "192.168.1.10/32"]),
            "restricted to 3 hosts (",
        ),
        (
            "the loopback network and a workstation",
            cidrs(&["127.0.0.0/8", "192.168.1.10/32"]),
            "restricted to 2 hosts (",
        ),
    ] {
        let dir = temp_dir();
        let (lines, _) = start_up(&break_glass(&dir, networks.clone(), None));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(lines.len(), 1, "{what}: {lines:?}");
        let (level, line) = &lines[0];
        assert_eq!(*level, tracing::Level::INFO, "{what}: {line}");
        assert!(line.contains(says), "{what}: {line}");
        for n in &networks {
            assert!(line.contains(&n.to_string()), "{what}: {line} names {n}");
        }
        for not in ["still open", "narrow", "default"] {
            assert!(!line.contains(not), "{what}: says `{not}`: {line}");
        }
    }
    // Not hosts: a /31 is two machines, a /30 four; they are ranges, like a /24.
    for networks in [
        cidrs(&["192.168.1.10/31"]),
        cidrs(&["192.168.1.8/30"]),
        cidrs(&["192.168.1.10/32", "192.168.1.0/24"]),
        cidrs(&["fd00::4/127"]),
    ] {
        let (warning, line) = break_glass_notice(&networks, &[]);
        assert!(warning, "{networks:?}: {line}");
        assert!(line.contains("still open"), "{line}");
    }
}

// REQ: API-004 (ADR-175) — the reminder about a proxy on this machine is for a list that names this
// machine, and it is not made when loopback is already a trusted proxy: `127.0.0.1` has to fall
// inside a listed network, as `remote()` tests the peer of a proxy on this machine. Another proxy
// network (an ingress), one address that isn't `127.0.0.1`, or `::1` does not count. A list with no
// loopback in it never gets it: a proxy on this machine would only be refused there. The page
// asks the same of the API (`loopbackIsTrustedProxy`), so the line and the card agree.
#[test]
fn api_004_the_loopback_hint_follows_the_trusted_proxy_list() {
    let with_loopback = [
        ("this machine", cidrs(&["127.0.0.0/8", "::1/128"])),
        ("one loopback host", cidrs(&["127.0.0.1/32"])),
        (
            "a loopback host and a workstation",
            cidrs(&["127.0.0.1/32", "192.168.1.10/32"]),
        ),
    ];
    let proxies: [(&[&str], bool); 8] = [
        (&[], false),
        (&["10.42.0.0/16"], false),
        (&["10.42.0.5/32"], false),
        (&["::1/128"], false),
        (&["127.0.0.2/32"], false),
        (&["127.0.0.1/32"], true),
        (&["127.0.0.0/8"], true),
        (&["10.42.0.0/16", "127.0.0.1/32"], true),
    ];
    for (what, networks) in &with_loopback {
        for (listed, trusted) in &proxies {
            let trusted_proxies = cidrs(listed);
            let (warning, line) = break_glass_notice(networks, &trusted_proxies);
            let ctx = format!("{what}, proxies {listed:?}: {line}");
            assert!(!warning, "{ctx}");
            assert_eq!(line.contains("trusted_proxies"), !trusted, "{ctx}");

            let mut c = break_glass(Path::new("/nonexistent/tt-hint"), networks.clone(), None);
            c.api.trusted_proxies = trusted_proxies;
            let policy = serde_json::to_value(settings(&c).password_login()).unwrap();
            assert_eq!(policy["includesLoopback"], true, "{ctx}");
            assert_eq!(policy["loopbackIsTrustedProxy"], *trusted, "{ctx}");
        }
    }
    // No loopback in the list: nothing to say, whatever the proxies.
    for networks in [
        cidrs(&["192.168.1.10/32"]),
        cidrs(&["192.168.1.10/32", "fd00::5/128"]),
    ] {
        for (listed, _) in &proxies {
            let (warning, line) = break_glass_notice(&networks, &cidrs(listed));
            assert!(!warning, "{networks:?}: {line}");
            assert!(!line.contains("trusted_proxies"), "{networks:?}: {line}");
        }
    }
}

// REQ: API-004 (issue #63) — a provider that can't be set up (a missing secret file) is exactly
// when break-glass matters, so the line is logged anyway, and the gate is in force all the same.
#[test]
fn api_004_start_up_says_it_even_when_the_provider_fails() {
    let dir = temp_dir();
    let c = break_glass(
        &dir,
        Config::default().auth.oidc.allowed_admin_networks,
        Some("/nonexistent/tt-oidc-secret"),
    );
    let (lines, provider_failed) = start_up(&c);
    assert!(provider_failed, "the provider did fail to set up");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].0, tracing::Level::WARN, "{lines:?}");
    assert!(lines[0].1.contains("still open"), "{lines:?}");
    // The gate does not depend on the provider: a public address is still refused.
    let auth = open(&c).unwrap();
    assert!(!auth.local_login_allowed("203.0.113.9".parse().unwrap()));
    assert!(auth.local_login_allowed("192.168.1.5".parse().unwrap()));
    drop(auth);
    let _ = std::fs::remove_dir_all(&dir);
}

// REQ: API-004 (issue #63, ADR-034) — pins the default: with `disable_local_login` on and the list
// left alone, the sign-in form is still offered to a client in a private network or on loopback
// (`/auth/status` says `localLogin` from this same check), and not to the Internet. Settings come
// from the default `Config` through `settings()`, so a change to the default list shows here.
#[test]
fn api_004_default_list_leaves_the_form_on_in_a_private_network() {
    let dir = temp_dir();
    let mut c = cfg(&dir);
    c.auth.oidc.disable_local_login = true;
    let auth = open(&c).unwrap();
    for ip in [
        "10.1.2.3",
        "172.17.0.1",
        "192.168.1.50",
        "100.64.0.9",
        "169.254.1.1",
        "127.0.0.1",
        "::1",
        "fd00::5",
        "fe80::1",
        "::ffff:192.168.1.5",
    ] {
        assert!(auth.local_login_allowed(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "203.0.113.9",
        "172.32.0.1",
        "100.128.0.1",
        "2001:db8::1",
    ] {
        assert!(!auth.local_login_allowed(ip.parse().unwrap()), "{ip}");
    }
    drop(auth);
    let _ = std::fs::remove_dir_all(&dir);
}

// REQ: API-004 (issue #63) — an empty list keeps its warning, whoever the provider is, and with
// the flag off there is nothing to say. (These two already held; they pin behaviour the change
// to the start-up line must not lose.)
#[test]
fn api_004_start_up_notice_follows_the_flag_and_the_list() {
    let dir = temp_dir();
    let (lines, _) = start_up(&break_glass(&dir, Vec::new(), None));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].0, tracing::Level::WARN);
    assert!(
        lines[0].1.contains("nobody can sign in with a password"),
        "{lines:?}"
    );

    let mut off = break_glass(&dir, Vec::new(), None);
    off.auth.oidc.disable_local_login = false;
    let (lines, _) = start_up(&off);
    assert!(lines.is_empty(), "flag off: {lines:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

// REQ: API-004 (issue #63), CLU-009 (ADR-120) — a Helm resolver pod has no way to sign in (its API
// has no Service port), so whatever the list, it gets information, not a warning per pod start.
#[test]
fn api_004_start_up_does_not_warn_a_resolver_pod() {
    for networks in [
        Config::default().auth.oidc.allowed_admin_networks,
        Vec::new(),
    ] {
        let dir = temp_dir();
        let mut pod = break_glass(&dir, networks.clone(), None);
        pod.cluster.ephemeral = true;
        let (lines, _) = start_up(&pod);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(lines.len(), 1, "{networks:?}: {lines:?}");
        assert_eq!(lines[0].0, tracing::Level::INFO, "{networks:?}: {lines:?}");
    }
}

// REQ: API-004 (issue #63, ADR-175) — the notice names every network and says when it is the
// default list. Which lists warn: any network that is neither this machine (127.0.0.0/8 or a part
// of it, `::1`) nor a single host (/32, /128), so a /7 around 127.0.0.0, `::1/64`, a /31 and the
// whole Internet do, and a workstation does not. (An IPv4-mapped form is a single host, which
// names a machine nobody connects from, not a network.)
#[test]
fn api_004_start_up_says_where_password_sign_in_is_still_open() {
    let default = Config::default().auth.oidc.allowed_admin_networks;
    assert!(
        !default.is_empty(),
        "the default break-glass list is not empty"
    );
    let (warning, line) = break_glass_notice(&default, &[]);
    assert!(warning, "the default list covers whole networks");
    for n in &default {
        assert!(line.contains(&n.to_string()), "{line} should name {n}");
    }
    assert!(
        line.contains("the default allowed_admin_networks"),
        "{line}"
    );
    let (warning, line) = break_glass_notice(&[], &[]);
    assert!(warning, "no break-glass network at all is a warning");
    assert!(line.contains("nobody can sign in with a password"));
    for (list, warns) in [
        ("127.0.0.1/32", false),
        ("127.0.0.0/8, ::1/128", false),
        ("127.1.2.3/32", false),
        ("192.168.1.10/32", false),
        ("fd00::5/128", false),
        ("127.0.0.0/8, 192.168.1.10/32", false),
        ("::ffff:127.0.0.1/128", false),
        ("127.0.0.0/7", true),
        ("0.0.0.0/0", true),
        ("::1/64", true),
        ("::/0", true),
        ("127.0.0.0/8, 10.0.0.0/8", true),
        ("192.168.1.10/31", true),
        ("192.168.1.0/24", true),
        ("192.168.1.10/32, 192.168.1.0/24", true),
        ("fd00::/64", true),
    ] {
        let nets = cidrs(&list.split(", ").collect::<Vec<_>>());
        let (warning, line) = break_glass_notice(&nets, &[]);
        assert_eq!(warning, warns, "{list}: {line}");
    }
}

// REQ: API-004 (issue #63, ADR-175) — what start-up says and what an admin is shown in Settings
// (`GET /users`, `passwordLogin`) are one fact: the same networks in the same order, the same
// answer to "does the list cover whole networks", and the same proxy hint. Both read it from
// `telltale_api::auth`, and this test is what keeps them from drifting apart. The block is read
// as the JSON the page gets, so the names the page reads are the ones pinned here.
#[test]
#[allow(clippy::too_many_lines)] // one story: every list against every proxy list, then the flag off
fn api_004_the_start_up_line_and_the_policy_agree() {
    use telltale_api::auth::{in_network, is_loopback_network};
    let lists: Vec<(&str, Vec<Cidr>)> = vec![
        (
            "the default list",
            Config::default().auth.oidc.allowed_admin_networks,
        ),
        ("loopback", cidrs(&["127.0.0.0/8", "::1/128"])),
        ("one loopback host", cidrs(&["127.0.0.1/32"])),
        ("one LAN host", cidrs(&["192.168.1.10/32"])),
        (
            "two LAN hosts, v4 and v6",
            cidrs(&["192.168.1.10/32", "fd00::5/128"]),
        ),
        (
            "loopback and one LAN host",
            cidrs(&["127.0.0.0/8", "192.168.1.5/32"]),
        ),
        ("a /31", cidrs(&["192.168.1.10/31"])),
        (
            "a LAN host and a /24",
            cidrs(&["192.168.1.10/32", "10.0.0.0/24"]),
        ),
        ("every address", cidrs(&["0.0.0.0/0"])),
        ("a /7 around 127.0.0.0", cidrs(&["127.0.0.0/7"])),
        ("::1/64", cidrs(&["::1/64"])),
        ("an IPv4-mapped loopback", cidrs(&["::ffff:127.0.0.1/128"])),
        ("an empty list", Vec::new()),
    ];
    for (what, networks) in lists {
        for proxies in [
            Vec::new(),
            cidrs(&["127.0.0.1/32"]),
            cidrs(&["10.42.0.0/16"]),
        ] {
            let mut c = break_glass(Path::new("/nonexistent/tt-agree"), networks.clone(), None);
            c.api.trusted_proxies = proxies.clone();
            let policy = serde_json::to_value(settings(&c).password_login()).unwrap();
            let (warning, line) = break_glass_notice(&networks, &proxies);
            let ctx = format!("{what}, {} proxies: {line}", proxies.len());

            assert_eq!(policy["restricted"], true, "{ctx}");
            let listed: Vec<String> = networks.iter().map(ToString::to_string).collect();
            assert_eq!(
                policy["networks"],
                serde_json::json!(listed),
                "the same networks: {ctx}"
            );
            let whole = policy["coversWholeNetworks"].as_bool().unwrap_or(false);
            let on_this_machine = policy["includesLoopback"].as_bool().unwrap_or(false);
            let proxy = policy["loopbackIsTrustedProxy"].as_bool().unwrap_or(false);
            assert_eq!(
                proxy,
                proxies
                    .iter()
                    .any(|p| in_network(IpAddr::from([127, 0, 0, 1]), p.addr, p.prefix)),
                "loopback is a proxy when 127.0.0.1 is inside a listed network: {ctx}"
            );
            assert_eq!(
                on_this_machine,
                networks
                    .iter()
                    .any(|n| is_loopback_network(n.addr, n.prefix)),
                "the list names this machine: {ctx}"
            );
            let loopback_only = !networks.is_empty()
                && networks
                    .iter()
                    .all(|n| is_loopback_network(n.addr, n.prefix));
            assert_eq!(
                line.contains("restricted to loopback"),
                loopback_only,
                "'restricted to loopback' is a list of nothing but this machine: {ctx}"
            );
            assert_eq!(
                line.contains(" host"),
                !networks.is_empty() && !whole && !loopback_only,
                "'restricted to N hosts' is a list of hosts, loopback among them or not: {ctx}"
            );
            assert_eq!(
                warning,
                networks.is_empty() || whole,
                "a warning when the list covers whole networks, or reaches nobody: {ctx}"
            );
            assert_eq!(
                line.contains("trusted_proxies"),
                !warning && on_this_machine && !proxy,
                "the hint shows for a list that names this machine while no proxy covers it: {ctx}"
            );
        }
    }

    // The flag off: nothing is restricted, and the list that is set is not reported.
    let mut off = break_glass(
        Path::new("/nonexistent/tt-agree"),
        Config::default().auth.oidc.allowed_admin_networks,
        None,
    );
    off.auth.oidc.disable_local_login = false;
    off.api.trusted_proxies = cidrs(&["127.0.0.1/32"]);
    let policy = serde_json::to_value(settings(&off).password_login()).unwrap();
    assert_eq!(
        policy,
        serde_json::json!({
            "restricted": false,
            "networks": [],
            "coversWholeNetworks": false,
            "includesLoopback": false,
            "loopbackIsTrustedProxy": false
        })
    );
}
