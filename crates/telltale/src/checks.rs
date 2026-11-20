//! Pre-save checks (REQ: API-002, T9.12): a draft upstream asked a probe, a draft list
//! downloaded and parsed, from this node, before either is saved. Nothing is kept.

use std::time::{Duration, Instant};

use telltale_api::model::CheckResult;
use telltale_api::problem::{Code, Problem};
use telltale_config::{Config, FilterList, Upstream};

/// The probe's time limit.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The body as `T`, with `name` filled in when it's missing (the path names saved entries).
fn draft<T: serde::de::DeserializeOwned>(
    mut body: serde_json::Value,
    what: &str,
) -> Result<T, Problem> {
    if let Some(o) = body.as_object_mut() {
        o.entry("name")
            .or_insert_with(|| serde_json::json!("check"));
    }
    serde_json::from_value(body).map_err(|e| {
        Problem::new(Code::InvalidConfig, format!("the {what}: {e}"))
            .hint(format!("Send the same fields as when saving the {what}."))
    })
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// REQ: API-002 (ADR-180) — whether `error` is about a TLS file `u` names (the router's messages
/// start with the file's path).
fn names_a_tls_file(u: &Upstream, error: &str) -> bool {
    [&u.tls_ca, &u.tls_client_cert, &u.tls_client_key]
        .into_iter()
        .flatten()
        .any(|p| error.contains(p.as_str()))
}

/// What a caller below admin is told when a TLS file can't be used: the same whatever is, or
/// isn't, at the path.
const TLS_FILE_ERROR: &str = "a TLS file it names (`tls_ca`, `tls_client_cert` or `tls_client_key`) couldn't be used; an administrator sees why, and the node's log says";

/// REQ: API-002 (T9.12) — builds the upstream as the router would (bootstrap, proxy, TLS,
/// stamps), and asks it what health checks ask (`. NS`, or a stub zone's SOA). `by_admin`: the
/// caller is an administrator (who alone is told what went wrong reading a TLS file).
pub(crate) async fn upstream(
    cfg: &Config,
    body: serde_json::Value,
    by_admin: bool,
) -> Result<CheckResult, Problem> {
    let u: Upstream = draft(body, "upstream")?;
    // REQ: UPS-011, API-002 (ADR-180) — refused before anything is built: a check starts no
    // program and connects to no local socket, for anyone.
    if let Some(field) = crate::managed::plugin_field(u.url.as_str(), !u.args.is_empty()) {
        return Err(crate::api_backend::plugin_refused(field));
    }
    // A configuration with only this upstream, in the default group.
    let mut c = cfg.clone();
    c.route.clear();
    c.upstream = vec![u.clone()];
    c.upstream_group = vec![draft(
        serde_json::json!({ "name": "default", "members": [u.name.as_str()] }),
        "upstream group",
    )?];
    let router = match telltale_upstream::Router::from_config(&c) {
        Ok(r) => r,
        Err(errors) => {
            let error = errors.join("; ");
            // REQ: API-002 (ADR-180) — what went wrong reading a TLS file (a line of it, whether
            // it is there) is an administrator's to see; the node's log has it.
            let error = if !by_admin && names_a_tls_file(&u, &error) {
                tracing::info!(upstream = %u.name, %error, "pre-save check: a TLS file couldn't be used");
                format!("upstream `{}`: {TLS_FILE_ERROR}", u.name)
            } else {
                error
            };
            return Ok(CheckResult {
                error: Some(error),
                detail: "not built".to_owned(),
                ..CheckResult::default()
            });
        }
    };
    let Some(up) = router.upstreams().first().cloned() else {
        return Ok(CheckResult {
            error: Some("not built".to_owned()),
            ..CheckResult::default()
        });
    };
    // REQ: UPS-006, DNS-022 — a stub upstream is judged as the background check judges it: up
    // when one of its servers answers the zone's SOA (a refusal counts, a SERVFAIL doesn't),
    // not by the rcode of a resolved answer.
    let started = Instant::now();
    let stub = tokio::time::timeout(PROBE_TIMEOUT, up.stub_liveness())
        .await
        .unwrap_or(Some(false));
    if let Some(alive) = stub {
        return Ok(CheckResult {
            ok: alive,
            error: (!alive).then(|| {
                "no server of the stub zone answered (a SERVFAIL doesn't count)".to_owned()
            }),
            detail: if alive {
                "a server of the stub zone answered".to_owned()
            } else {
                "no answer".to_owned()
            },
            elapsed_ms: ms(started.elapsed()),
            ..CheckResult::default()
        });
    }
    // Any other upstream: the question health checks ask (the root's NS records).
    let probe = up.health_question();
    let started = Instant::now();
    let r = up.exchange(&probe, PROBE_TIMEOUT).await;
    let elapsed_ms = ms(started.elapsed());
    Ok(match r {
        Ok(resp) => {
            let s = telltale_proto::summarize(&resp).ok();
            let rcode = s
                .as_ref()
                .map_or(telltale_proto::rcode::SERVFAIL, |s| s.rcode);
            let answers = s.as_ref().map_or(0, |s| s.answers);
            let ok = rcode == telltale_proto::rcode::NOERROR;
            let name = crate::api_backend::rcode_name(u8::try_from(rcode).unwrap_or(2));
            CheckResult {
                ok,
                error: (!ok).then(|| format!("answered {name}")),
                detail: format!("answered {name}, {answers} records"),
                elapsed_ms,
                ..CheckResult::default()
            }
        }
        Err(e) => CheckResult {
            error: Some(e.to_string()),
            detail: "no answer".to_owned(),
            elapsed_ms,
            ..CheckResult::default()
        },
    })
}

/// REQ: API-002 (T9.12) — downloads `url` (with `[filter]`'s limits) or takes `rules`, and
/// parses them as the compiler would.
pub(crate) async fn list(cfg: &Config, body: serde_json::Value) -> Result<CheckResult, Problem> {
    let l: FilterList = draft(body, "list")?;
    let started = Instant::now();
    let data: Vec<u8> = if let Some(url) = &l.url {
        let client = telltale_filter::fetch::Client::new(
            std::sync::Arc::new(telltale_filter::fetch::SystemResolver),
            &[],
        )
        .map_err(|e| Problem::internal(format!("the download client: {e}")))?
        .allow_link_local(cfg.filter.allow_link_local_urls);
        let max = l.max_bytes.unwrap_or(cfg.filter.max_list_bytes).bytes();
        let timeout = Duration::from_secs(u64::from(cfg.filter.fetch_timeout_secs.max(1)));
        let got = tokio::time::timeout(
            timeout,
            client.get(
                url.as_str(),
                &telltale_filter::fetch::Conditional::default(),
                max,
            ),
        )
        .await;
        match got {
            Ok(Ok(telltale_filter::fetch::Response::Body { data, .. })) => data,
            Ok(Ok(telltale_filter::fetch::Response::NotModified)) => Vec::new(),
            Ok(Err(e)) => {
                return Ok(CheckResult {
                    error: Some(e.message),
                    detail: "not downloaded".to_owned(),
                    elapsed_ms: ms(started.elapsed()),
                    ..CheckResult::default()
                });
            }
            Err(_) => {
                return Ok(CheckResult {
                    error: Some(format!("timed out after {} s", timeout.as_secs())),
                    detail: "not downloaded".to_owned(),
                    elapsed_ms: ms(started.elapsed()),
                    ..CheckResult::default()
                });
            }
        }
    } else if !l.rules.is_empty() {
        l.rules
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    } else {
        return Err(Problem::new(
            Code::InvalidConfig,
            "the list has no `url` or `rules` to check",
        )
        .hint("A `path` list is checked when it's saved."));
    };
    let opts = telltale_filter::parse::ListOptions {
        kind: l.kind,
        match_mode: l.match_mode,
    };
    let stats = telltale_filter::parse::parse_list(&data, opts, |_, _| {});
    let warnings = stats
        .samples
        .iter()
        .take(10)
        .map(|s| {
            format!(
                "line {}: {} ({})",
                s.line,
                s.text.chars().take(120).collect::<String>(),
                s.reason
            )
        })
        .collect();
    let ok = stats.rules > 0;
    Ok(CheckResult {
        ok,
        error: (!ok).then(|| {
            "no rules found: is it a block list (hosts, domains, or Adblock syntax)?".to_owned()
        }),
        detail: format!(
            "{} rules from {} lines ({} invalid, {} unsupported)",
            stats.rules, stats.lines, stats.invalid, stats.unsupported
        ),
        elapsed_ms: ms(started.elapsed()),
        rules: Some(stats.rules),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        telltale_config::Loader::new()
            .toml_str("t.toml", "")
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config
    }

    /// REQ: API-002 (T9.12) — an upstream that answers is ok; one that doesn't says why; a
    /// mistyped body is a 422.
    #[tokio::test]
    async fn api_002_check_upstream() {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            while let Ok((n, from)) = s.recv_from(&mut b).await {
                let q = telltale_proto::parse_query(&b[..n]).unwrap();
                let mut out = [0u8; 512];
                let len = telltale_proto::ResponseBuilder::new(
                    &q,
                    &mut out,
                    telltale_proto::rcode::NOERROR,
                )
                .unwrap()
                .finish(None)
                .unwrap();
                let _ = s.send_to(&out[..len], from).await;
            }
        });
        let r = upstream(
            &cfg(),
            serde_json::json!({ "url": format!("udp://{addr}") }),
            false,
        )
        .await
        .unwrap();
        assert!(r.ok, "{r:?}");
        assert_eq!(r.detail, "answered NOERROR, 0 records");
        // Nothing listens on port 9 of 127.0.0.2: a timeout or a refusal, not ok.
        let r = upstream(
            &cfg(),
            serde_json::json!({ "url": "tcp://127.0.0.1:9" }),
            false,
        )
        .await
        .unwrap();
        assert!(!r.ok && r.error.is_some(), "{r:?}");
        let r = upstream(&cfg(), serde_json::json!({ "url": "gopher://x" }), false)
            .await
            .unwrap();
        assert!(!r.ok && r.detail == "not built", "{r:?}");
        assert!(
            r.error.as_deref().unwrap_or("").contains("gopher"),
            "a build error without a TLS file is shown to everyone: {r:?}"
        );
        assert!(
            upstream(&cfg(), serde_json::json!({ "url": 7 }), true)
                .await
                .is_err()
        );
        assert!(
            upstream(&cfg(), serde_json::json!({ "uri": "udp://1.1.1.1" }), true)
                .await
                .is_err()
        );
    }

    /// REQ: API-002 (T9.12) — inline rules parse; a list with nothing usable isn't ok and
    /// shows its lines; no source is a 422; an unreachable URL says why.
    #[tokio::test]
    async fn api_002_check_list() {
        let r = list(
            &cfg(),
            serde_json::json!({ "rules": ["ads.example", "||track.example^", "||odd.example^$frobnicate"] }),
        )
        .await
        .unwrap();
        assert!(r.ok, "{r:?}");
        assert_eq!(r.rules, Some(2));
        assert_eq!(r.warnings.len(), 1, "the unknown modifier: {r:?}");
        let r = list(&cfg(), serde_json::json!({ "rules": ["##.banner"] }))
            .await
            .unwrap();
        assert!(!r.ok && r.rules == Some(0));
        assert!(
            list(&cfg(), serde_json::json!({ "kind": "block" }))
                .await
                .is_err()
        );
        let r = list(
            &cfg(),
            serde_json::json!({ "url": "http://127.0.0.1:9/list.txt" }),
        )
        .await
        .unwrap();
        assert!(!r.ok && r.detail == "not downloaded", "{r:?}");
    }
}
