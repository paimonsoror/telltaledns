//! REQ: T8.2, API-010, FLT-006 — FRITZ!Box TR-064 Hosts on a configured private route.
//! Without a sign-in (the box's "allow access for applications"), one request a host; with a
//! user and its password (ADR-190), HTTP Digest and the whole list in one file.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use md5::Digest as _;

use roxmltree::{Document, Node};
use telltale_config::{Cidr, RouterConfig};
use telltale_filter::fetch::Client;

use super::{Device, Polled};

const HOSTS: &str = "urn:dslforum-org:service:Hosts:1";
const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
/// A box that claims more fails the poll: nothing of a partial list is used.
/// 1,024 at about 70 ms a request (a VPN) fits [`POLL_CEILING`].
const MAX_HOSTS: usize = 1_024;
/// Most bytes one SOAP answer may have.
const MAX_ANSWER: u64 = 256 * 1024;
/// Most bytes the signed-in host list may have: [`MAX_HOSTS`] rows of about 1.5 KiB.
const MAX_LIST: usize = 4 << 20;
/// Hosts are read one request each (a few ms to a few hundred over a VPN), so the budget is
/// per request, not per poll.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// ponytail: a ceiling on the whole read, so a crawling box can't hold up the other routers;
/// a box that reaches it without a sign-in is read faster with one (the whole list at once).
const POLL_CEILING: Duration = Duration::from_secs(120);

fn field<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|child| child.has_tag_name(name))
        .and_then(|child| child.text())
        .map(str::trim)
}

fn control_path<'a>(doc: &'a Document<'_>) -> Result<&'a str, String> {
    doc.descendants()
        .filter(|node| node.has_tag_name("service"))
        .find(|node| field(*node, "serviceType") == Some(HOSTS))
        .and_then(|node| field(node, "controlURL"))
        .filter(|path| path.starts_with('/') && !path.starts_with("//"))
        .ok_or_else(|| "FRITZ!Box does not advertise a local TR-064 Hosts control path".into())
}

/// One host: a `GetGenericHostEntry` answer (`prefix` `New`) or a row of the host list (no
/// prefix). Only active hosts in `networks`.
fn host(row: Node<'_, '_>, prefix: &str, networks: &[Cidr]) -> Option<Device> {
    let get = |name: &str| field(row, &format!("{prefix}{name}"));
    if !matches!(get("Active"), Some("1" | "true")) {
        return None;
    }
    let ip: Ipv4Addr = get("IPAddress")?.parse().ok()?;
    if !networks.iter().any(|net| net.contains(ip.into())) {
        return None;
    }
    let mac = get("MACAddress").unwrap_or_default().to_ascii_lowercase();
    let name = get("HostName")
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    Some((mac, ip, name))
}

/// One exchange within [`REQUEST_TIMEOUT`], at most `max` bytes.
async fn exchange(
    client: &Client,
    request: http::Request<Vec<u8>>,
    max: u64,
) -> Result<http::Response<Vec<u8>>, String> {
    tokio::time::timeout(REQUEST_TIMEOUT, client.request(request, max))
        .await
        .map_err(|_| "TR-064 request timed out")?
        .map_err(|e| e.message)
}

/// The status and the body (a SOAP fault comes as HTTP 500 with a body).
fn text(response: http::Response<Vec<u8>>) -> Result<(http::StatusCode, String), String> {
    let status = response.status();
    let body =
        String::from_utf8(response.into_body()).map_err(|_| "TR-064 returned non-UTF-8 XML")?;
    Ok((status, body))
}

async fn request(
    client: &Client,
    request: http::Request<Vec<u8>>,
) -> Result<(http::StatusCode, String), String> {
    text(exchange(client, request, MAX_ANSWER).await?)
}

/// A user and its password.
type Login = (String, String);

/// The parameters of a `WWW-Authenticate: Digest` challenge (names lower-cased), or `None`
/// for another scheme.
fn challenge(header: &str) -> Option<HashMap<String, String>> {
    let (scheme, mut rest) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("digest") {
        return None;
    }
    let mut params = HashMap::new();
    loop {
        rest = rest.trim_start_matches([' ', ',']);
        let Some((name, after)) = rest.split_once('=') else {
            break;
        };
        let (value, after) = if let Some(quoted) = after.strip_prefix('"') {
            // A quoted string: `\` escapes the next character.
            let mut value = String::new();
            let mut chars = quoted.char_indices();
            let mut end = None;
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => value.extend(chars.next().map(|(_, c)| c)),
                    '"' => {
                        end = Some(i + 1);
                        break;
                    }
                    c => value.push(c),
                }
            }
            (value, &quoted[end?..])
        } else {
            let end = after.find(',').unwrap_or(after.len());
            (after[..end].trim().to_owned(), &after[end..])
        };
        params.insert(name.trim().to_ascii_lowercase(), value);
        rest = after;
    }
    Some(params)
}

fn md5_hex(input: &str) -> String {
    md5::Md5::digest(input.as_bytes())
        .iter()
        .fold(String::new(), |mut hex, b| {
            let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{b:02x}"));
            hex
        })
}

/// A quoted-string's content (RFC 7616 §3.4).
fn quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The `Authorization` answering `challenge` for `method` `uri` (RFC 7616, MD5: the one
/// algorithm FRITZ!OS offers; `qop=auth` when the box offers it, else RFC 2069's form).
fn authorization(
    (user, password): &Login,
    method: &str,
    uri: &str,
    challenge: &HashMap<String, String>,
    cnonce: &str,
) -> Result<String, String> {
    let get = |name: &str| challenge.get(name).map(String::as_str);
    if !get("algorithm").is_none_or(|a| a.eq_ignore_ascii_case("md5")) {
        return Err("TR-064 asks for a digest algorithm other than MD5".into());
    }
    let (Some(realm), Some(nonce)) = (get("realm"), get("nonce")) else {
        return Err("TR-064 sent a Digest challenge without realm or nonce".into());
    };
    let ha1 = md5_hex(&format!("{user}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let auth = get("qop").is_some_and(|q| q.split(',').any(|q| q.trim() == "auth"));
    let (qop, response) = if auth {
        (
            format!(", qop=auth, nc=00000001, cnonce=\"{cnonce}\""),
            md5_hex(&format!("{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}")),
        )
    } else {
        (String::new(), md5_hex(&format!("{ha1}:{nonce}:{ha2}")))
    };
    let opaque = get("opaque")
        .map(|o| format!(", opaque=\"{}\"", quoted(o)))
        .unwrap_or_default();
    Ok(format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", algorithm=MD5{qop}, response=\"{response}\"{opaque}",
        quoted(user),
        quoted(realm),
        quoted(nonce),
        quoted(uri)
    ))
}

fn ok((status, body): (http::StatusCode, String)) -> Result<String, String> {
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("TR-064 HTTP {status}"))
    }
}

/// `UPnP` error 713, `SpecifiedArrayIndexInvalid`: the list ended (a host left since the count).
fn past_the_end((status, body): &(http::StatusCode, String)) -> bool {
    *status == http::StatusCode::INTERNAL_SERVER_ERROR
        && Document::parse(body).is_ok_and(|doc| {
            doc.descendants()
                .any(|n| n.has_tag_name("errorCode") && n.text() == Some("713"))
        })
}

fn xml(body: &str) -> Result<Document<'_>, String> {
    Document::parse(body).map_err(|_| "TR-064 returned invalid XML".into())
}

/// A Hosts action at `base` `path`; with a `login`, signed in when the box asks (HTTP 401).
async fn action(
    client: &Client,
    (base, path): (&str, &str),
    name: &str,
    args: &str,
    login: Option<&Login>,
) -> Result<(http::StatusCode, String), String> {
    let body = format!(
        "<s:Envelope xmlns:s=\"{SOAP}\"><s:Body><u:{name} xmlns:u=\"{HOSTS}\">{args}</u:{name}></s:Body></s:Envelope>"
    );
    let build = |auth: Option<&str>| {
        let mut req = http::Request::post(format!("{base}{path}"))
            .header("content-type", "text/xml; charset=utf-8")
            .header("soapaction", format!("\"{HOSTS}#{name}\""));
        if let Some(auth) = auth {
            req = req.header(http::header::AUTHORIZATION, auth);
        }
        req.body(body.clone().into_bytes())
            .map_err(|_| "invalid TR-064 request".to_owned())
    };
    let Some(login) = login else {
        return request(client, build(None)?).await;
    };
    let first = exchange(client, build(None)?, MAX_ANSWER).await?;
    if first.status() != http::StatusCode::UNAUTHORIZED {
        return text(first);
    }
    let digest = first
        .headers()
        .get_all(http::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(challenge)
        .ok_or("TR-064 asks for a sign-in other than HTTP Digest")?;
    let cnonce =
        crate::router_secrets::random_hex().ok_or("no random source for TR-064 sign-in")?;
    let auth = authorization(login, "POST", path, &digest, &cnonce)?;
    let answer = request(client, build(Some(&auth))?).await?;
    if answer.0 == http::StatusCode::UNAUTHORIZED {
        return Err("TR-064 HTTP 401: the box refused the username and password".into());
    }
    Ok(answer)
}

fn response<'a, 'input>(doc: &'a Document<'input>, name: &str) -> Result<Node<'a, 'input>, String> {
    doc.root_element()
        .children()
        .find(|node| node.has_tag_name((SOAP, "Body")))
        .and_then(|body| {
            body.children()
                .find(|node| node.has_tag_name((HOSTS, name)))
        })
        .ok_or_else(|| format!("TR-064 did not return {name}"))
}

/// REQ: T8.2, FLT-006 (ADR-190) — the host list file. The box sends it with `Connection: close`
/// and no length, and over TLS closes without `close_notify`, which reads as an error after the
/// last byte (a cut the TLS layer can't rule out). So a body that ends in an error counts only if
/// it is a whole XML document: one cut short doesn't parse.
async fn list_body(client: &Client, req: http::Request<Vec<u8>>) -> Result<String, String> {
    let read = async {
        let (head, mut body) = client.request_stream(req).await.map_err(|e| e.message)?;
        if !head.status.is_success() {
            return Err(format!("TR-064 HTTP {}", head.status));
        }
        let mut data = Vec::new();
        let mut cut = None;
        while let Some(chunk) = body.next_chunk().await {
            match chunk {
                Ok(chunk) if data.len() + chunk.len() > MAX_LIST => {
                    return Err(format!("TR-064 host list larger than {MAX_LIST} bytes"));
                }
                Ok(chunk) => data.extend_from_slice(&chunk),
                Err(e) => {
                    cut = Some(e.message);
                    break;
                }
            }
        }
        let list = String::from_utf8(data).map_err(|_| "TR-064 returned non-UTF-8 XML")?;
        match cut {
            Some(e) if Document::parse(&list).is_err() => {
                Err(format!("TR-064 host list ended early: {e}"))
            }
            _ => Ok(list),
        }
    };
    tokio::time::timeout(REQUEST_TIMEOUT, read)
        .await
        .map_err(|_| "TR-064 request timed out".to_owned())?
}

/// REQ: T8.2, FLT-006 (ADR-190) — signed in: the whole host list in one file, from the path
/// `X_AVM-DE_GetHostListPath` gives (it carries a session ID, so it needs no sign-in itself).
async fn host_list(
    client: &Client,
    control: (&str, &str),
    login: &Login,
    networks: &[Cidr],
) -> Result<Polled, String> {
    let answer = action(client, control, "X_AVM-DE_GetHostListPath", "", Some(login)).await?;
    let answer = ok(answer)?;
    let doc = xml(&answer)?;
    let path = field(
        response(&doc, "X_AVM-DE_GetHostListPathResponse")?,
        "NewX_AVM-DE_HostListPath",
    )
    .filter(|path| path.starts_with('/') && !path.starts_with("//"))
    .ok_or("FRITZ!Box did not return a local host list path")?;
    let req = http::Request::get(format!("{}{path}", control.0))
        .body(Vec::new())
        .map_err(|_| "invalid TR-064 host list path")?;
    let list = list_body(client, req).await?;
    let doc = xml(&list)?;
    let rows: Vec<_> = doc
        .root_element()
        .children()
        .filter(|node| node.has_tag_name("Item"))
        .collect();
    if rows.len() > MAX_HOSTS {
        return Err("invalid TR-064 host count".into());
    }
    Ok(Polled::now(
        rows.into_iter()
            .filter_map(|row| host(row, "", networks))
            .collect(),
    ))
}

async fn hosts(client: &Client, router: &RouterConfig) -> Result<Polled, String> {
    let networks = router
        .client_subnets
        .iter()
        .map(|subnet| Cidr::parse(subnet.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    // REQ: T8.2 (ADR-190) — a user and its password, or neither (the validation pairs them).
    let login = match router.username.as_deref() {
        Some(user) => Some((
            user.to_owned(),
            super::secret(router.password_file.as_ref())?.ok_or("set password_file")?,
        )),
        None => None,
    };
    let base = router.url.trim_end_matches('/');
    let desc = http::Request::get(format!("{base}/tr64desc.xml"))
        .body(Vec::new())
        .map_err(|_| "invalid FRITZ!Box URL")?;
    let desc = ok(request(client, desc).await?)?;
    let doc = xml(&desc)?;
    let control = (base, control_path(&doc)?);
    if let Some(login) = &login {
        return host_list(client, control, login, &networks).await;
    }
    let count = ok(action(client, control, "GetHostNumberOfEntries", "", None).await?)?;
    let doc = xml(&count)?;
    let count = field(
        response(&doc, "GetHostNumberOfEntriesResponse")?,
        "NewHostNumberOfEntries",
    )
    .and_then(|count| count.parse::<usize>().ok())
    .filter(|count| *count <= MAX_HOSTS)
    .ok_or("invalid TR-064 host count")?;
    let mut seen = Vec::with_capacity(count);
    for index in 0..count {
        let args = format!("<NewIndex>{index}</NewIndex>");
        let answer = action(client, control, "GetGenericHostEntry", &args, None).await?;
        if past_the_end(&answer) {
            break;
        }
        let body = ok(answer)?;
        let doc = xml(&body)?;
        seen.extend(host(
            response(&doc, "GetGenericHostEntryResponse")?,
            "New",
            &networks,
        ));
    }
    Ok(Polled::now(seen))
}

pub(super) async fn poll(client: &Client, router: &RouterConfig) -> Result<Polled, String> {
    tokio::time::timeout(POLL_CEILING, hosts(client, router))
        .await
        .map_err(|_| "TR-064 host poll timed out".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Polls a fake box that reports `count` hosts and answers entry `i` with `entry(i)`.
    async fn poll_fake(count: usize, entry: fn(usize) -> (u16, String)) -> Result<Polled, String> {
        use axum::{
            Router,
            http::{HeaderMap, StatusCode},
            routing::{get, post},
        };
        use std::sync::Arc;
        use telltale_filter::fetch::SystemResolver;

        let app = Router::new()
            .route("/tr64desc.xml", get(|| async {
                format!("<root><device><serviceList><service><serviceType>{HOSTS}</serviceType><controlURL>/hosts</controlURL></service></serviceList></device></root>")
            }))
            .route("/hosts", post(move |headers: HeaderMap, body: String| async move {
                let action = headers["soapaction"].to_str().unwrap();
                let envelope = |name: &str, output: &str| {
                    format!("<s:Envelope xmlns:s=\"{SOAP}\"><s:Body><u:{name}Response xmlns:u=\"{HOSTS}\">{output}</u:{name}Response></s:Body></s:Envelope>")
                };
                if action == format!("\"{HOSTS}#GetHostNumberOfEntries\"") {
                    let output = format!("<NewHostNumberOfEntries>{count}</NewHostNumberOfEntries>");
                    return (StatusCode::OK, envelope("GetHostNumberOfEntries", &output));
                }
                assert_eq!(action, format!("\"{HOSTS}#GetGenericHostEntry\""));
                let index = body.split("<NewIndex>").nth(1).and_then(|s| s.split('<').next());
                let (status, output) = entry(index.unwrap().parse().unwrap());
                let body = if status == 200 {
                    envelope("GetGenericHostEntry", &output)
                } else {
                    format!("<s:Envelope xmlns:s=\"{SOAP}\"><s:Body><s:Fault><detail><UPnPError xmlns=\"urn:dslforum-org:control-1-0\"><errorCode>{output}</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>")
                };
                (StatusCode::from_u16(status).unwrap(), body)
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let router: RouterConfig = serde_json::from_value(serde_json::json!({
            "name": "site-a",
            "type": "fritzbox",
            "url": format!("http://{}", listener.local_addr().unwrap()),
            "client_subnets": ["192.168.40.0/24"]
        }))
        .unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = Client::new(Arc::new(SystemResolver), &[]).unwrap();
        let result = poll(&client, &router).await;
        server.abort();
        result
    }

    fn tablet(_: usize) -> (u16, String) {
        (200, "<NewIPAddress>192.168.40.2</NewIPAddress><NewActive>1</NewActive><NewHostName>Tablet</NewHostName><NewMACAddress>02:AA:BB:CC:DD:EE</NewMACAddress>".into())
    }

    #[tokio::test]
    async fn flt_006_fritzbox_polls_the_advertised_hosts_service() {
        let result = poll_fake(1, tablet).await.unwrap();
        assert_eq!(
            result.now,
            [(
                "02:aa:bb:cc:dd:ee".into(),
                Ipv4Addr::new(192, 168, 40, 2),
                Some("Tablet".into())
            )]
        );
    }

    #[tokio::test]
    async fn flt_006_fritzbox_ends_the_list_at_a_713_fault_and_fails_on_others() {
        let shrunk = |i| {
            if i < 2 {
                tablet(i)
            } else {
                (500, "713".into())
            }
        };
        assert_eq!(poll_fake(5, shrunk).await.unwrap().now.len(), 2);
        let broken = |i| {
            if i < 2 {
                tablet(i)
            } else {
                (500, "501".into())
            }
        };
        assert!(poll_fake(5, broken).await.is_err());
    }

    #[tokio::test]
    async fn flt_006_fritzbox_over_the_host_cap_fails_closed() {
        let never = |_| panic!("no entry is read");
        assert!(poll_fake(MAX_HOSTS + 1, never).await.is_err());
    }

    /// RFC 2617 §3.5's example, and RFC 2069's form when the box offers no `qop`.
    #[test]
    fn t8_2_fritzbox_digest_answers_the_challenge() {
        let login = ("Mufasa".to_owned(), "Circle Of Life".to_owned());
        let digest = challenge(
            "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
        )
        .unwrap();
        let header = authorization(&login, "GET", "/dir/index.html", &digest, "0a4f113b").unwrap();
        assert!(
            header.contains("response=\"6629fae49393a05397450978507c4ef1\""),
            "{header}"
        );
        assert!(
            header.contains("qop=auth, nc=00000001, cnonce=\"0a4f113b\""),
            "{header}"
        );
        assert!(
            header.contains("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""),
            "{header}"
        );
        let plain = challenge("Digest realm=\"r\", nonce=\"n\", algorithm=MD5").unwrap();
        let header = authorization(&login, "POST", "/x", &plain, "c").unwrap();
        let ha1 = md5_hex("Mufasa:r:Circle Of Life");
        let expected = md5_hex(&format!("{ha1}:n:{}", md5_hex("POST:/x")));
        assert!(
            header.contains(&format!("response=\"{expected}\"")),
            "{header}"
        );
        assert!(!header.contains("qop"), "{header}");
        let sha = challenge("Digest realm=\"r\", nonce=\"n\", algorithm=SHA-256").unwrap();
        assert!(authorization(&login, "POST", "/x", &sha, "c").is_err());
        assert!(challenge("Basic realm=\"r\"").is_none());
        let escaped = challenge(r#"Digest realm="a \"b\", c", nonce=n"#).unwrap();
        assert_eq!(escaped["realm"], "a \"b\", c");
        assert_eq!(escaped["nonce"], "n");
    }

    /// A signed-in box: the Hosts action answers 401 with a Digest challenge until signed in
    /// with `secret`, then gives the host list's path, which needs no sign-in.
    async fn poll_signed_in(password: &str) -> Result<Polled, String> {
        use axum::{
            Router,
            extract::RawQuery,
            http::{HeaderMap, StatusCode, header},
            response::IntoResponse,
            routing::{get, post},
        };
        use std::sync::Arc;
        use telltale_filter::fetch::SystemResolver;

        let app = Router::new()
            .route("/tr64desc.xml", get(|| async {
                format!("<root><device><serviceList><service><serviceType>{HOSTS}</serviceType><controlURL>/upnp/control/hosts</controlURL></service></serviceList></device></root>")
            }))
            .route("/upnp/control/hosts", post(|headers: HeaderMap| async move {
                let refuse = (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Digest realm=\"F!Box SOAP-Auth\", nonce=\"5E1F\", algorithm=MD5, qop=\"auth\"")],
                )
                    .into_response();
                let Some(auth) = headers.get(header::AUTHORIZATION) else {
                    return refuse;
                };
                let got = challenge(auth.to_str().unwrap()).unwrap();
                let ha1 = md5_hex("telltale:F!Box SOAP-Auth:secret");
                let ha2 = md5_hex("POST:/upnp/control/hosts");
                let want = md5_hex(&format!("{ha1}:5E1F:00000001:{}:auth:{ha2}", got["cnonce"]));
                if got["response"] != want || got["uri"] != "/upnp/control/hosts" {
                    return refuse;
                }
                assert_eq!(headers["soapaction"], format!("\"{HOSTS}#X_AVM-DE_GetHostListPath\"").as_str());
                let body = format!("<s:Envelope xmlns:s=\"{SOAP}\"><s:Body><u:X_AVM-DE_GetHostListPathResponse xmlns:u=\"{HOSTS}\"><NewX_AVM-DE_HostListPath>/devicehostlist.lua?sid=0123</NewX_AVM-DE_HostListPath></u:X_AVM-DE_GetHostListPathResponse></s:Body></s:Envelope>");
                body.into_response()
            }))
            .route("/devicehostlist.lua", get(|RawQuery(query): RawQuery| async move {
                assert_eq!(query.as_deref(), Some("sid=0123"));
                "<List>
                  <Item><Index>1</Index><IPAddress>192.168.40.2</IPAddress><MACAddress>02:AA:BB:CC:DD:EE</MACAddress><Active>1</Active><HostName>Tablet</HostName></Item>
                  <Item><Index>2</Index><IPAddress>192.168.40.3</IPAddress><MACAddress>02:AA:BB:CC:DD:EF</MACAddress><Active>0</Active><HostName>Away</HostName></Item>
                  <Item><Index>3</Index><IPAddress>192.168.50.2</IPAddress><MACAddress>02:AA:BB:CC:DD:F0</MACAddress><Active>1</Active><HostName>Elsewhere</HostName></Item>
                </List>"
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dir = std::env::temp_dir().join(format!(
            "telltale-fritz-{}",
            crate::router_secrets::random_hex().unwrap()
        ));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("password");
        std::fs::write(&file, format!("{password}\n")).unwrap();
        let router: RouterConfig = serde_json::from_value(serde_json::json!({
            "name": "site-a",
            "type": "fritzbox",
            "url": format!("http://{}", listener.local_addr().unwrap()),
            "client_subnets": ["192.168.40.0/24"],
            "username": "telltale",
            "password_file": file.to_str().unwrap(),
        }))
        .unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = Client::new(Arc::new(SystemResolver), &[]).unwrap();
        let result = poll(&client, &router).await;
        server.abort();
        std::fs::remove_dir_all(&dir).unwrap();
        result
    }

    /// The box closes the list's connection without ending it cleanly (TLS: no
    /// `close_notify`): a whole document still counts, one cut short doesn't.
    #[tokio::test]
    async fn t8_2_fritzbox_host_list_ending_in_an_error_counts_only_whole() {
        use std::sync::Arc;
        use telltale_filter::fetch::SystemResolver;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        for (body, whole) in [("<List><Item/></List>", true), ("<List><Item/>", false)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await.unwrap();
                // The length promises more than is sent: the read ends in an error.
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len() + 10
                );
                socket.write_all(head.as_bytes()).await.unwrap();
                socket.write_all(body.as_bytes()).await.unwrap();
            });
            let client = Client::new(Arc::new(SystemResolver), &[]).unwrap();
            let req = http::Request::get(format!("http://{addr}/devicehostlist.lua?sid=1"))
                .body(Vec::new())
                .unwrap();
            let got = list_body(&client, req).await;
            server.await.unwrap();
            assert_eq!(got.is_ok(), whole, "{body}: {got:?}");
        }
    }

    #[tokio::test]
    async fn t8_2_fritzbox_signed_in_reads_the_whole_host_list() {
        let result = poll_signed_in("secret").await.unwrap();
        assert_eq!(
            result.now,
            [(
                "02:aa:bb:cc:dd:ee".into(),
                Ipv4Addr::new(192, 168, 40, 2),
                Some("Tablet".into())
            )]
        );
        let refused = poll_signed_in("wrong").await.err().unwrap();
        assert!(refused.contains("username and password"), "{refused}");
    }

    #[test]
    fn flt_006_fritzbox_uses_only_active_hosts_in_the_configured_network() {
        let doc = xml("<rows>
            <row><NewIPAddress>192.168.40.2</NewIPAddress><NewActive>1</NewActive><NewHostName>Tablet &amp; keyboard</NewHostName><NewMACAddress>02:AA:BB:CC:DD:EE</NewMACAddress></row>
            <row><NewIPAddress>192.168.40.3</NewIPAddress><NewActive>true</NewActive><NewHostName>Phone</NewHostName></row>
            <row><NewIPAddress>192.168.40.4</NewIPAddress><NewActive>0</NewActive></row>
            <row><NewIPAddress>192.168.50.2</NewIPAddress><NewActive>1</NewActive></row>
        </rows>").unwrap();
        let networks = [Cidr::parse("192.168.40.0/24").unwrap()];
        let rows: Vec<_> = doc
            .root_element()
            .children()
            .filter_map(|node| host(node, "New", &networks))
            .collect();
        assert_eq!(
            rows,
            [
                (
                    "02:aa:bb:cc:dd:ee".into(),
                    Ipv4Addr::new(192, 168, 40, 2),
                    Some("Tablet & keyboard".into())
                ),
                (
                    String::new(),
                    Ipv4Addr::new(192, 168, 40, 3),
                    Some("Phone".into())
                ),
            ]
        );
    }
}
