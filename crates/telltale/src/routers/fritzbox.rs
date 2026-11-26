//! REQ: T8.2, API-010, FLT-006 — FRITZ!Box TR-064 Hosts on a configured private route.

use std::net::Ipv4Addr;
use std::time::Duration;

use roxmltree::{Document, Node};
use telltale_config::{Cidr, RouterConfig};
use telltale_filter::fetch::Client;

use super::{Device, Polled};

const HOSTS: &str = "urn:dslforum-org:service:Hosts:1";
const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const MAX_HOSTS: usize = 2_048;

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

async fn request(client: &Client, request: http::Request<Vec<u8>>) -> Result<String, String> {
    let response = client
        .request(request, 256 * 1024)
        .await
        .map_err(|e| e.message)?;
    if !response.status().is_success() {
        return Err(format!("TR-064 HTTP {}", response.status()));
    }
    String::from_utf8(response.into_body()).map_err(|_| "TR-064 returned non-UTF-8 XML".into())
}

fn xml(body: &str) -> Result<Document<'_>, String> {
    Document::parse(body).map_err(|_| "TR-064 returned invalid XML".into())
}

async fn action(client: &Client, uri: &str, name: &str, args: &str) -> Result<String, String> {
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
    let endpoint: http::Uri = router.url.parse().map_err(|_| "invalid FRITZ!Box URL")?;
    let authority = endpoint.authority().ok_or("FRITZ!Box URL needs a host")?;
    if authority.as_str().contains('@') || endpoint.path() != "/" || endpoint.query().is_some() {
        return Err("FRITZ!Box URL must be an origin without credentials, path or query".into());
    }
    let base = router.url.trim_end_matches('/');
    let desc = http::Request::get(format!("{base}/tr64desc.xml"))
        .body(Vec::new())
        .map_err(|_| "invalid FRITZ!Box URL")?;
    let desc = request(client, desc).await?;
    let doc = xml(&desc)?;
    let uri = format!("{base}{}", control_path(&doc)?);
    let count = action(client, &uri, "GetHostNumberOfEntries", "").await?;
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
        let body = action(client, &uri, "GetGenericHostEntry", &args).await?;
        let doc = xml(&body)?;
        seen.extend(host(
            response(&doc, "GetGenericHostEntryResponse")?,
            &networks,
        ));
    }
    Ok(Polled::now(seen))
}

pub(super) async fn poll(client: &Client, router: &RouterConfig) -> Result<Polled, String> {
    tokio::time::timeout(Duration::from_secs(15), hosts(client, router))
        .await
        .map_err(|_| "TR-064 host poll timed out".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn flt_006_fritzbox_polls_the_advertised_hosts_service() {
        use axum::{
            Router,
            http::HeaderMap,
            routing::{get, post},
        };
        use std::sync::Arc;
        use telltale_filter::fetch::SystemResolver;

        let app = Router::new()
            .route("/tr64desc.xml", get(|| async {
                format!("<root><device><serviceList><service><serviceType>{HOSTS}</serviceType><controlURL>/hosts</controlURL></service></serviceList></device></root>")
            }))
            .route("/hosts", post(|headers: HeaderMap, body: String| async move {
                let action = headers["soapaction"].to_str().unwrap();
                let (name, output) = if action == format!("\"{HOSTS}#GetHostNumberOfEntries\"") {
                    ("GetHostNumberOfEntries", "<NewHostNumberOfEntries>1</NewHostNumberOfEntries>")
                } else {
                    assert_eq!(action, format!("\"{HOSTS}#GetGenericHostEntry\""));
                    assert!(body.contains("<NewIndex>0</NewIndex>"));
                    ("GetGenericHostEntry", "<NewIPAddress>192.168.40.2</NewIPAddress><NewActive>1</NewActive><NewHostName>Tablet</NewHostName><NewMACAddress>02:AA:BB:CC:DD:EE</NewMACAddress>")
                };
                format!("<s:Envelope xmlns:s=\"{SOAP}\"><s:Body><u:{name}Response xmlns:u=\"{HOSTS}\">{output}</u:{name}Response></s:Body></s:Envelope>")
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
        let result = poll(&client, &router).await.unwrap();
        assert_eq!(
            result.now,
            [(
                "02:aa:bb:cc:dd:ee".into(),
                Ipv4Addr::new(192, 168, 40, 2),
                Some("Tablet".into())
            )]
        );
        server.abort();
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
