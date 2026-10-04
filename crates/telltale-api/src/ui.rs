//! The embedded web UI (REQ: API-005, ADR-009, ADR-030): `ui/dist` compiled into the binary,
//! served at `/` on the API listener with a strict CSP (`spec/08` §6: no inline scripts,
//! `X-Frame-Options: DENY`). Hashed assets are cached forever; `index.html` never is.
//! `npm run build` writes a `.gz` next to each text file, served when the browser accepts
//! gzip. A build without `ui/dist` still compiles and serves a short page saying so.

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::Embed)]
#[folder = "../../ui/dist"]
#[allow_missing = true]
struct Assets;

/// Content Security Policy for every UI response. Styles are only stylesheets: the UI sets
/// dynamic styles through the CSSOM, which CSP allows, never through `style` attributes.
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
    font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
    frame-ancestors 'none'";

const MISSING: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>TelltaleDNS</title></head>\
    <body><h1>TelltaleDNS</h1><p>This build has no web UI. Build it with <code>npm --prefix ui ci &amp;&amp; \
    npm --prefix ui run build</code>, then rebuild the binary. The API is at \
    <a href=\"/api/v1/openapi.json\">/api/v1/openapi.json</a>.</p></body></html>";

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map_or("", |(_, ext)| ext) {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "json" | "map" => "application/json",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn security_headers(h: &mut HeaderMap) {
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|e| {
            let mut parts = e.trim().split(';');
            parts.next() == Some("gzip") && !parts.any(|q| q.trim().replace(' ', "") == "q=0")
        })
}

/// Serves a UI file (`/` is `index.html`); anything else is 404.
pub fn serve(method: &Method, uri: &Uri, headers: &HeaderMap) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = match uri.path().trim_start_matches('/') {
        "" | "index.html" => "index.html",
        p => p,
    };
    if path
        .split('/')
        .any(|seg| seg.is_empty() || seg == ".." || seg == ".")
        || std::path::Path::new(path)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let gz = accepts_gzip(headers)
        .then(|| Assets::get(&format!("{path}.gz")))
        .flatten();
    let (body, encoded) = match gz {
        Some(f) => (f.data, true),
        None => match Assets::get(path) {
            Some(f) => (f.data, false),
            None if path == "index.html" => (MISSING.as_bytes().into(), false),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    let mut resp = body.into_owned().into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(path)),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    h.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    if encoded {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    security_headers(h);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_005_gzip_negotiation_and_types() {
        let mut h = HeaderMap::new();
        assert!(!accepts_gzip(&h));
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("br, gzip;q=0.8"),
        );
        assert!(accepts_gzip(&h));
        h.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip;q=0, br"),
        );
        assert!(!accepts_gzip(&h));
        assert_eq!(
            content_type("assets/index-1.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(content_type("favicon.svg"), "image/svg+xml");
    }
}
