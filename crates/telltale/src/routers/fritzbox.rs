//! REQ: T8.2, API-010, FLT-006 — FRITZ!Box TR-064 Hosts on a configured private route.

use std::net::Ipv4Addr;
use std::time::Duration;

use roxmltree::{Document, Node};
use telltale_config::{Cidr, RouterConfig};
use telltale_filter::fetch::Client;

use super::{Device, Polled};

const HOSTS: &str = "urn:dslforum-org:service:Hosts:1";
const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
/// A box that claims more fails the poll: nothing of a partial list is used.
const MAX_HOSTS: usize = 2_048;
/// Hosts are read one request each (a few ms to a few hundred over a VPN), so the budget is
/// per request, not per poll.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// ponytail: a ceiling on the whole read, so a crawling box can't hold up the other routers;
/// read in parallel or use `X_AVM-DE_GetHostListPath` (needs sign-in) if boxes ever reach it.
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

fn host(row: Node<'_, '_>, networks: &[Cidr]) -> Option<Device> {
    if !matches!(field(row, "NewActive"), Some("1" | "true")) {
        return None;
    }
    let ip: Ipv4Addr = field(row, "NewIPAddress")?.parse().ok()?;
    if !networks.iter().any(|net| net.contains(ip.into())) {
        return None;
    }
    let mac = field(row, "NewMACAddress")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let name = field(row, "NewHostName")
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    Some((mac, ip, name))
}

/// One exchange within [`REQUEST_TIMEOUT`]; the status and the body (a SOAP fault comes as
/// HTTP 500 with a body).
async fn request(
    client: &Client,
    request: http::Request<Vec<u8>>,
) -> Result<(http::StatusCode, String), String> {
    let response = tokio::time::timeout(REQUEST_TIMEOUT, client.request(request, 256 * 1024))
        .await
        .map_err(|_| "TR-064 request timed out")?
        .map_err(|e| e.message)?;
    let status = response.status();
    let body =
        String::from_utf8(response.into_body()).map_err(|_| "TR-064 returned non-UTF-8 XML")?;
    Ok((status, body))
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

async fn action(
    client: &Client,
    uri: &str,
    name: &str,
    args: &str,
) -> Result<(http::StatusCode, String), String> {
    let body = format!(
        "<s:Envelope xmlns:s=\"{SOAP}\"><s:Body><u:{name} xmlns:u=\"{HOSTS}\">{args}</u:{name}></s:Body></s:Envelope>"
    );
    let req = http::Request::post(uri)
        .header("content-type", "text/xml; charset=utf-8")
        .header("soapaction", format!("\"{HOSTS}#{name}\""))
        .body(body.into_bytes())
        .map_err(|_| "invalid TR-064 request")?;
    request(client, req).await
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

async fn hosts(client: &Client, router: &RouterConfig) -> Result<Polled, String> {
    let networks = router
        .client_subnets
        .iter()
        .map(|subnet| Cidr::parse(subnet.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    let base = router.url.trim_end_matches('/');
    let desc = http::Request::get(format!("{base}/tr64desc.xml"))
        .body(Vec::new())
        .map_err(|_| "invalid FRITZ!Box URL")?;
    let desc = ok(request(client, desc).await?)?;
    let doc = xml(&desc)?;
    let uri = format!("{base}{}", control_path(&doc)?);
    let count = ok(action(client, &uri, "GetHostNumberOfEntries", "").await?)?;
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
        let answer = action(client, &uri, "GetGenericHostEntry", &args).await?;
        if past_the_end(&answer) {
            break;
        }
        let body = ok(answer)?;
        let doc = xml(&body)?;
        seen.extend(host(
            response(&doc, "GetGenericHostEntryResponse")?,
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
            .filter_map(|node| host(node, &networks))
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
