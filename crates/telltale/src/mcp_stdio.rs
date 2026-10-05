//! `telltale mcp --stdio` (REQ: AGT-006; T6.6, ADR-065): the MCP stdio transport for agents
//! that start their servers as subprocesses. Each newline-delimited JSON-RPC message from
//! stdin is posted to a node's `/mcp` with an API token, and the answer is written to stdout.
//! One implementation of the tools (the node's), whichever transport the agent speaks.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Most bytes one answer may have.
const MAX_ANSWER: u64 = 16 << 20;

/// Bridges stdin/stdout to `url` (`http://host:port`) with `token` until stdin closes.
pub(crate) async fn run(url: &str, token: &str) -> Result<(), String> {
    let client =
        telltale_filter::fetch::Client::new(Arc::new(telltale_filter::fetch::SystemResolver), &[])?;
    let endpoint = format!("{}/mcp", url.trim_end_matches('/'));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    let mut session: Option<String> = None;
    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut req = http::Request::post(endpoint.as_str())
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(s) = &session {
            req = req.header("mcp-session-id", s.as_str());
        }
        let req = req
            .body(line.as_bytes().to_vec())
            .map_err(|e| e.to_string())?;
        let answer = match client.request(req, MAX_ANSWER).await {
            Ok(resp) => {
                if let Some(s) = resp
                    .headers()
                    .get("mcp-session-id")
                    .and_then(|v| v.to_str().ok())
                {
                    session = Some(s.to_owned());
                }
                let status = resp.status();
                let body = resp.into_body();
                if status == http::StatusCode::ACCEPTED || body.is_empty() {
                    None // a notification
                } else if status.is_success() || body.starts_with(b"{") || body.starts_with(b"[") {
                    Some(body)
                } else {
                    Some(error_for(line, &format!("the node answered HTTP {status}")))
                }
            }
            Err(e) => Some(error_for(
                line,
                &format!("can't reach {endpoint}: {}", e.message),
            )),
        };
        if let Some(mut a) = answer {
            // One message per line (MCP stdio framing).
            a.retain(|&b| b != b'\n' && b != b'\r');
            a.push(b'\n');
            out.write_all(&a).await.map_err(|e| e.to_string())?;
            out.flush().await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// A JSON-RPC error for the request on `line` (nothing for a notification).
fn error_for(line: &str, message: &str) -> Vec<u8> {
    let id = serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": message}
    }))
    .unwrap_or_default()
}
