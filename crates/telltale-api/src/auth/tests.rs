use std::net::{IpAddr, Ipv4Addr};

use super::*;

const T0: u64 = 1_791_072_000;
const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

fn auth(settings: Settings) -> Auth {
    Auth::new(Arc::new(State::in_memory().unwrap()), settings)
}

#[test]
fn api_003_first_run_setup_token_creates_one_admin() {
    let a = auth(Settings::default());
    assert!(a.setup_required().unwrap());
    let token = a.setup_token().unwrap().unwrap();
    assert_eq!(
        a.setup_token().unwrap().as_deref(),
        Some(token.as_str()),
        "stable until used"
    );
    let e = a
        .setup("wrong", "admin", "long enough password", T0)
        .unwrap_err();
    assert_eq!(e.code, Code::Unauthorized);
    let e = a.setup(&token, "admin", "short", T0).unwrap_err();
    assert_eq!(e.code, Code::InvalidParameter, "password policy");
    let u = a
        .setup(&token, "admin", "long enough password", T0)
        .unwrap();
    assert_eq!(u.role, "admin");
    assert!(!a.setup_required().unwrap());
    assert_eq!(a.setup_token().unwrap(), None);
    let e = a
        .setup(&token, "second", "long enough password", T0)
        .unwrap_err();
    assert_eq!(e.code, Code::Conflict, "only once");
}

#[test]
fn api_003_login_lockout_and_unknown_users() {
    let a = auth(Settings::default());
    a.create_user("ana", "correct horse battery", Role::Viewer, false, T0)
        .unwrap();
    for i in 0..FREE_ATTEMPTS {
        let e = a
            .login("ana", "wrong password!", None, None, IP, T0 + u64::from(i))
            .unwrap_err();
        assert_eq!(e.code, Code::Unauthorized);
    }
    // The sixth failure locks the username (and the address).
    let e = a
        .login("ana", "wrong password!", None, None, IP, T0 + 10)
        .unwrap_err();
    assert_eq!(e.code, Code::Unauthorized);
    let e = a
        .login("ana", "correct horse battery", None, None, IP, T0 + 11)
        .unwrap_err();
    assert_eq!(e.code, Code::RateLimited, "even the right password waits");
    let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let e = a
        .login("ana", "correct horse battery", None, None, other, T0 + 11)
        .unwrap_err();
    assert_eq!(
        e.code,
        Code::RateLimited,
        "the username is locked from anywhere"
    );
    assert!(
        a.login("ana", "correct horse battery", None, None, other, T0 + 41)
            .is_ok()
    ); // REQ: API-006 — the lock (not each failure) is audited, once per key.
    let locks = a
        .state()
        .audit_page(None, 10, Some("auth.lockout"), None)
        .unwrap();
    assert_eq!(locks.len(), 2, "the username and the address");
    assert!(
        locks
            .iter()
            .any(|e| e.target == "ana" && e.detail.contains("\"failures\":6"))
    );
    // Unknown users fail exactly like wrong passwords.
    let e = a
        .login("nobody", "whatever password", None, None, other, T0 + 50)
        .unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (Code::Unauthorized, "wrong username or password")
    );
}

#[test]
fn api_003_totp_codes_are_single_use_and_recovery_codes_work_once() {
    let a = auth(Settings::default());
    let u = a
        .create_user("ana", "correct horse battery", Role::Admin, false, T0)
        .unwrap();
    let secret = b"12345678901234567890";
    a.state().set_totp(u.id, Some(secret), true).unwrap();
    let e = a
        .login("ana", "correct horse battery", None, None, IP, 59)
        .unwrap_err();
    assert_eq!(e.code, Code::TotpRequired);
    assert!(
        a.login("ana", "correct horse battery", Some("287082"), None, IP, 59)
            .is_ok()
    );
    let e = a
        .login("ana", "correct horse battery", Some("287082"), None, IP, 60)
        .unwrap_err();
    assert_eq!(e.code, Code::Unauthorized, "a code can't be replayed");
    let (codes, hashes) = crypto::recovery_codes();
    a.state().set_recovery_codes(u.id, &hashes).unwrap();
    assert!(
        a.login(
            "ana",
            "correct horse battery",
            None,
            Some(&codes[3]),
            IP,
            61
        )
        .is_ok()
    );
    let e = a
        .login(
            "ana",
            "correct horse battery",
            None,
            Some(&codes[3]),
            IP,
            62,
        )
        .unwrap_err();
    assert_eq!(e.code, Code::Unauthorized, "recovery codes are single-use");
}

#[test]
fn api_003_roles_can_require_totp() {
    let a = auth(Settings {
        totp_required_roles: vec![Role::Admin],
        ..Settings::default()
    });
    a.create_user("root", "correct horse battery", Role::Admin, false, T0)
        .unwrap();
    a.create_user("ana", "correct horse battery", Role::Viewer, false, T0)
        .unwrap();
    let e = a
        .login("root", "correct horse battery", None, None, IP, T0)
        .unwrap_err();
    assert_eq!(e.code, Code::Forbidden, "admins must enroll TOTP first");
    assert!(
        a.login("ana", "correct horse battery", None, None, IP, T0)
            .is_ok()
    );
}

#[test]
fn api_003_sessions_expire_when_idle_and_tokens_are_scoped() {
    let a = auth(Settings::default());
    let u = a
        .create_user("op", "correct horse battery", Role::Operator, false, T0)
        .unwrap();
    let s = a.start_session(&u, IP, T0).unwrap();
    let p = Presented {
        session: Some(&s.cookie),
        ..Presented::default()
    };
    let who = a.authenticate(&p, T0 + 10).unwrap().unwrap();
    assert_eq!((who.username.as_str(), who.role), ("op", Role::Operator));
    assert!(matches!(who.via, Via::Session { .. }));
    assert_eq!(
        a.authenticate(&p, T0 + 86_401).unwrap(),
        None,
        "idle for a day"
    );

    // Tokens: `tt_<id>_<secret>`, hashed at rest, scope caps the owner's role.
    let (id, secret) = (crypto::random_id(), crypto::random_secret());
    a.state()
        .create_token(
            &id,
            u.id,
            "grafana",
            &crypto::secret_hash(&secret),
            "read",
            Some(T0 + 100),
            T0,
        )
        .unwrap();
    let bearer = format!("tt_{id}_{secret}");
    let p = Presented {
        bearer: Some(&bearer),
        ..Presented::default()
    };
    assert_eq!(a.authenticate(&p, T0).unwrap().unwrap().role, Role::Viewer);
    assert_eq!(
        a.authenticate(&p, T0 + 100).unwrap_err().code,
        Code::Unauthorized,
        "expired"
    );
    for bad in [
        "tt_nope",
        &format!("tt_{id}_wrong"),
        &format!("xx_{id}_{secret}"),
    ] {
        let p = Presented {
            bearer: Some(bad),
            ..Presented::default()
        };
        assert_eq!(
            a.authenticate(&p, T0).unwrap_err().code,
            Code::Unauthorized,
            "{bad}"
        );
    }
    // A disabled owner's token stops working.
    a.state()
        .create_token(
            "aaaaaaaaaaaaaaaa",
            u.id,
            "x",
            &crypto::secret_hash("s3cret"),
            "admin",
            None,
            T0,
        )
        .unwrap();
    let p = Presented {
        bearer: Some("tt_aaaaaaaaaaaaaaaa_s3cret"),
        ..Presented::default()
    };
    assert_eq!(
        a.authenticate(&p, T0).unwrap().unwrap().role,
        Role::Operator,
        "capped by the owner"
    );
    a.state().update_user(u.id, None, Some(true), None).unwrap();
    assert_eq!(a.authenticate(&p, T0).unwrap_err().code, Code::Unauthorized);
}

#[test]
fn api_003_http_basic_is_opt_in_and_needs_https() {
    let a = auth(Settings::default());
    let u = a
        .create_user("prom", "correct horse battery", Role::Viewer, true, T0)
        .unwrap();
    a.create_user("ana", "correct horse battery", Role::Viewer, false, T0)
        .unwrap();
    let basic = |user: &str, https| Presented {
        basic: Some((user.to_owned(), "correct horse battery".to_owned())),
        https,
        ..Presented::default()
    };
    assert_eq!(
        a.authenticate(&basic("prom", false), T0).unwrap_err().code,
        Code::Unauthorized
    );
    assert_eq!(
        a.authenticate(&basic("prom", true), T0)
            .unwrap()
            .unwrap()
            .via,
        Via::Basic
    );
    assert_eq!(
        a.authenticate(&basic("ana", true), T0).unwrap_err().code,
        Code::Forbidden,
        "not opted in"
    );
    // Cached for a minute, but a change (here: disabling) takes effect immediately.
    a.state().update_user(u.id, None, Some(true), None).unwrap();
    assert_eq!(
        a.authenticate(&basic("prom", true), T0 + 1)
            .unwrap_err()
            .code,
        Code::Unauthorized
    );
    let lax = auth(Settings {
        allow_insecure_basic: true,
        ..Settings::default()
    });
    lax.create_user("prom", "correct horse battery", Role::Viewer, true, T0)
        .unwrap();
    assert!(
        lax.authenticate(&basic("prom", false), T0)
            .unwrap()
            .is_some()
    );
}

#[test]
fn api_003_bootstrap_admin_from_a_secret_runs_only_on_first_start() {
    let dir = std::env::temp_dir().join(format!("tt-setup-{}", crypto::random_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("setup-token");
    std::fs::write(&file, "from-file").unwrap();
    let a = auth(Settings {
        setup_token_file: Some(file.clone()),
        ..Settings::default()
    });
    a.set_setup_token("from-file".into());
    assert_eq!(a.setup_token().unwrap().as_deref(), Some("from-file"));
    let e = a
        .bootstrap_admin(
            "root",
            None,
            Some("$argon2i$v=19$m=16,t=2,p=1$c2FsdHNhbHQ$aGFzaA"),
            T0,
        )
        .unwrap_err();
    assert_eq!(e.code, Code::InvalidParameter, "argon2id only");
    let hash = crypto::hash_password("correct horse battery").unwrap();
    let u = a
        .bootstrap_admin("root", None, Some(&hash), T0)
        .unwrap()
        .unwrap();
    assert_eq!(u.role, "admin");
    assert!(
        !file.exists(),
        "the setup token is gone once an admin exists"
    );
    assert_eq!(a.setup_token().unwrap(), None);
    assert!(
        a.login("root", "correct horse battery", None, None, IP, T0)
            .is_ok()
    );
    // Later starts leave existing users alone.
    assert!(
        a.bootstrap_admin("root", Some("another password!"), None, T0)
            .unwrap()
            .is_none()
    );
    assert!(
        a.login("root", "correct horse battery", None, None, IP, T0)
            .is_ok()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
