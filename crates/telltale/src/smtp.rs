//! A small SMTP client for alert email (REQ: OBS-010; T9.4, ADR-085): submission over STARTTLS
//! (port 587), implicit TLS (465), or, only when asked for by name, plain TCP for a local mail
//! catcher. AUTH PLAIN or LOGIN. One message per connection; written from RFC 5321 (SMTP),
//! RFC 3207 (STARTTLS), RFC 4954 (AUTH), and RFC 5322/2045/2047 (the message).
//!
//! Alerts are rare, so there's no connection pool; every step has a timeout.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// How a connection is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Security {
    /// `smtp://host:587`: plain, then STARTTLS (required: no fallback to plain).
    StartTls,
    /// `smtps://host:465`: TLS from the first byte.
    Tls,
    /// `smtp+insecure://host:1025`: never encrypted (local mail catchers only).
    None,
}

/// Where and how to send.
#[derive(Debug, Clone)]
pub(crate) struct Server {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) security: Security,
    /// AUTH, when set.
    pub(crate) login: Option<(String, String)>,
    /// Extra trusted certificates (a private mail server); the Mozilla roots are always in.
    pub(crate) extra_roots: Vec<CertificateDer<'static>>,
}

/// One message.
#[derive(Debug, Clone)]
pub(crate) struct Message {
    pub(crate) from: String,
    pub(crate) to: Vec<String>,
    pub(crate) subject: String,
    pub(crate) body: String,
}

const STEP: Duration = Duration::from_secs(20);

/// Parses `smtp://`, `smtps://`, or `smtp+insecure://` `host[:port]`.
pub(crate) fn parse_url(url: &str) -> Result<(String, u16, Security), String> {
    let (security, rest, default_port) = if let Some(r) = url.strip_prefix("smtps://") {
        (Security::Tls, r, 465)
    } else if let Some(r) = url.strip_prefix("smtp+insecure://") {
        (Security::None, r, 25)
    } else if let Some(r) = url.strip_prefix("smtp://") {
        (Security::StartTls, r, 587)
    } else {
        return Err("use smtp://host:587 (STARTTLS), smtps://host:465 (TLS), or smtp+insecure://host:port (no encryption, local catchers only)".into());
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => (
            h.trim_start_matches('[').trim_end_matches(']').to_owned(),
            p.parse::<u16>().map_err(|_| format!("bad port `{p}`"))?,
        ),
        _ => (rest.to_owned(), default_port),
    };
    if host.is_empty() {
        return Err("no host".into());
    }
    Ok((host, port, security))
}

/// RFC 2047 for a header with non-ASCII text.
fn header_text(s: &str) -> String {
    if s.is_ascii() && !s.contains(['\r', '\n']) {
        s.to_owned()
    } else {
        let clean: String = s.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        format!(
            "=?UTF-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(clean.as_bytes())
        )
    }
}

/// An address safe to put in `MAIL FROM:<...>` and headers.
fn valid_address(a: &str) -> bool {
    let a = a.trim();
    !a.is_empty()
        && a.len() <= 254
        && a.contains('@')
        && !a.contains(['<', '>', '\r', '\n', ' ', ','])
}

/// The RFC 5322 message: headers, then the body in base64 (any text, any line length).
pub(crate) fn render(m: &Message, now_unix: u64, id: u64) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(m.body.as_bytes());
    let mut wrapped = String::with_capacity(body.len() + body.len() / 76 * 2);
    for chunk in body.as_bytes().chunks(76) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        wrapped.push_str("\r\n");
    }
    let domain = m.from.rsplit_once('@').map_or("telltale.local", |(_, d)| d);
    format!(
        "From: TelltaleDNS <{from}>\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: <{id:016x}.{now_unix}@{domain}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\nAuto-Submitted: auto-generated\r\nX-Mailer: TelltaleDNS\r\n\r\n{wrapped}",
        from = m.from,
        to = m.to.join(", "),
        subject = header_text(&m.subject),
        date = rfc5322_date(now_unix),
    )
}

/// `Tue, 06 Oct 2026 17:05:52 +0000`.
fn rfc5322_date(unix: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix / 86_400;
    let secs = unix % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        DAYS[usize::try_from(days % 7).unwrap_or(0)],
        d,
        MONTHS[usize::try_from(m - 1).unwrap_or(0)],
        y,
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// One server reply: its code and the text of every line.
async fn reply<S: AsyncRead + Unpin>(r: &mut BufReader<S>) -> Result<(u16, Vec<String>), String> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(STEP, r.read_line(&mut line))
            .await
            .map_err(|_| "the mail server stopped answering".to_owned())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("the mail server closed the connection".into());
        }
        if line.len() > 2048 || lines.len() > 100 {
            return Err("the mail server's reply is too long".into());
        }
        let line = line.trim_end().to_owned();
        let code: u16 = line
            .get(..3)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| format!("not an SMTP reply: {line:.80}"))?;
        let last = line.as_bytes().get(3) != Some(&b'-');
        lines.push(line.get(4..).unwrap_or("").to_owned());
        if last {
            return Ok((code, lines));
        }
    }
}

/// Sends `line` and checks the reply's code is one of `want`.
async fn cmd<S: AsyncRead + AsyncWrite + Unpin>(
    r: &mut BufReader<S>,
    line: &str,
    want: &[u16],
    shown: &str,
) -> Result<Vec<String>, String> {
    let w = r.get_mut();
    tokio::time::timeout(STEP, async {
        w.write_all(line.as_bytes()).await?;
        w.write_all(b"\r\n").await?;
        w.flush().await
    })
    .await
    .map_err(|_| "the mail server stopped reading".to_owned())?
    .map_err(|e| e.to_string())?;
    let (code, text) = reply(r).await?;
    if want.contains(&code) {
        Ok(text)
    } else {
        Err(format!(
            "{shown}: {code} {}",
            text.join(" ").chars().take(200).collect::<String>()
        ))
    }
}

fn tls(extra: &[CertificateDer<'static>]) -> Result<tokio_rustls::TlsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for c in extra {
        roots.add(c.clone()).map_err(|e| e.to_string())?;
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
}

/// Our name in EHLO.
fn ehlo_name() -> String {
    let h = std::env::var("HOSTNAME").unwrap_or_default();
    if !h.is_empty()
        && h.len() < 200
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        h
    } else {
        "telltale.local".to_owned()
    }
}

/// The dialog after the greeting (and after STARTTLS): EHLO, AUTH, the envelope, the data.
async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    r: &mut BufReader<S>,
    server: &Server,
    m: &Message,
    data: &str,
    encrypted: bool,
) -> Result<(), String> {
    let ext = cmd(r, &format!("EHLO {}", ehlo_name()), &[250], "EHLO").await?;
    if let Some((user, pass)) = &server.login {
        if !encrypted {
            return Err("refusing to send a password without encryption".into());
        }
        let auth = ext
            .iter()
            .find(|l| l.to_ascii_uppercase().starts_with("AUTH"))
            .map(|l| l.to_ascii_uppercase())
            .unwrap_or_default();
        let b64 = |s: &[u8]| base64::engine::general_purpose::STANDARD.encode(s);
        if auth.contains("PLAIN") || !auth.contains("LOGIN") {
            let token = b64(format!("\0{user}\0{pass}").as_bytes());
            cmd(
                r,
                &format!("AUTH PLAIN {token}"),
                &[235],
                "sign-in (AUTH PLAIN)",
            )
            .await?;
        } else {
            cmd(r, "AUTH LOGIN", &[334], "sign-in (AUTH LOGIN)").await?;
            cmd(r, &b64(user.as_bytes()), &[334], "sign-in (user name)").await?;
            cmd(r, &b64(pass.as_bytes()), &[235], "sign-in (password)").await?;
        }
    }
    cmd(r, &format!("MAIL FROM:<{}>", m.from), &[250], "sender").await?;
    for to in &m.to {
        cmd(
            r,
            &format!("RCPT TO:<{to}>"),
            &[250, 251],
            &format!("recipient {to}"),
        )
        .await?;
    }
    cmd(r, "DATA", &[354], "DATA").await?;
    // Dot-stuffing (RFC 5321 §4.5.2); our lines are base64 or headers, but be correct anyway.
    let mut body = String::with_capacity(data.len() + 8);
    for line in data.split("\r\n") {
        if line.starts_with('.') {
            body.push('.');
        }
        body.push_str(line);
        body.push_str("\r\n");
    }
    while body.ends_with("\r\n\r\n") {
        body.truncate(body.len() - 2);
    }
    body.push('.');
    cmd(r, &body, &[250], "message").await?;
    let _ = cmd(r, "QUIT", &[221], "QUIT").await;
    Ok(())
}

/// Sends `m` through `server`.
pub(crate) async fn send(server: &Server, m: &Message) -> Result<(), String> {
    if !valid_address(&m.from) {
        return Err(format!("`from`: `{}` isn't an email address", m.from));
    }
    if m.to.is_empty() || !m.to.iter().all(|t| valid_address(t)) {
        return Err("`to`: give one or more email addresses".into());
    }
    let data = render(m, crate::pipeline::unix_now(), rand::random());
    let tcp = tokio::time::timeout(
        STEP,
        TcpStream::connect((server.host.as_str(), server.port)),
    )
    .await
    .map_err(|_| format!("{}:{}: no answer", server.host, server.port))?
    .map_err(|e| format!("{}:{}: {e}", server.host, server.port))?;
    let name = ServerName::try_from(server.host.clone()).map_err(|e| e.to_string())?;
    match server.security {
        Security::Tls => {
            let s = tokio::time::timeout(STEP, tls(&server.extra_roots)?.connect(name, tcp))
                .await
                .map_err(|_| "TLS handshake timed out".to_owned())?
                .map_err(|e| format!("TLS: {e}"))?;
            let mut r = BufReader::new(s);
            expect_greeting(&mut r).await?;
            session(&mut r, server, m, &data, true).await
        }
        Security::None => {
            let mut r = BufReader::new(tcp);
            expect_greeting(&mut r).await?;
            session(&mut r, server, m, &data, false).await
        }
        Security::StartTls => {
            let mut r = BufReader::new(tcp);
            expect_greeting(&mut r).await?;
            let ext = cmd(&mut r, &format!("EHLO {}", ehlo_name()), &[250], "EHLO").await?;
            if !ext.iter().any(|l| l.eq_ignore_ascii_case("STARTTLS")) {
                return Err(
                    "the mail server doesn't offer STARTTLS (use smtps:// for port 465)".into(),
                );
            }
            cmd(&mut r, "STARTTLS", &[220], "STARTTLS").await?;
            if !r.buffer().is_empty() {
                return Err("the mail server sent data before TLS started".into());
            }
            let s = tokio::time::timeout(
                STEP,
                tls(&server.extra_roots)?.connect(name, r.into_inner()),
            )
            .await
            .map_err(|_| "TLS handshake timed out".to_owned())?
            .map_err(|e| format!("TLS: {e}"))?;
            let mut r = BufReader::new(s);
            session(&mut r, server, m, &data, true).await
        }
    }
}

async fn expect_greeting<S: AsyncRead + Unpin>(r: &mut BufReader<S>) -> Result<(), String> {
    let (code, text) = reply(r).await?;
    if code == 220 {
        Ok(())
    } else {
        Err(format!("greeting: {code} {}", text.join(" ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: OBS-010 (T9.4) — URLs say how to connect; plain needs its own scheme.
    #[test]
    fn obs_010_smtp_urls() {
        assert_eq!(
            parse_url("smtp://smtp.gmail.com").unwrap(),
            ("smtp.gmail.com".into(), 587, Security::StartTls)
        );
        assert_eq!(
            parse_url("smtps://mail.example.com:2465").unwrap(),
            ("mail.example.com".into(), 2465, Security::Tls)
        );
        assert_eq!(
            parse_url("smtp+insecure://127.0.0.1:1025").unwrap(),
            ("127.0.0.1".into(), 1025, Security::None)
        );
        assert!(parse_url("http://x").is_err());
        assert!(parse_url("smtp://:25").is_err());
    }

    /// REQ: OBS-010 (T9.4) — the message: encoded subject, base64 body, a correct date.
    #[test]
    fn obs_010_smtp_message() {
        let m = Message {
            from: "dns@example.com".into(),
            to: vec!["me@example.com".into(), "you@example.com".into()],
            subject: "Upstream down: quad9 ⚠".into(),
            body: "line one\n.dot line".into(),
        };
        let r = render(&m, 1_791_306_352, 7);
        assert!(r.contains("To: me@example.com, you@example.com\r\n"));
        assert!(r.contains("Subject: =?UTF-8?B?"));
        assert!(
            r.contains("Date: Tue, 06 Oct 2026 17:05:52 +0000\r\n"),
            "{r}"
        );
        assert!(r.contains("Content-Transfer-Encoding: base64"));
        assert_eq!(rfc5322_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert!(!valid_address("a@b>\r\nRCPT TO:<x@y"));
    }
}
