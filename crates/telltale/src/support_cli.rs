//! REQ: OPS-011 (ADR-156) — `telltale support-package`: make the package from the command line.
//!
//! By default it asks a running node for it through the API, with an API token (an admin's:
//! `TELLTALE_TOKEN` or `--token-file`), so it has the live state. Without a token, or with
//! `--offline`, it builds a smaller one from the configuration files and the log files under the
//! data directory, which is what you want when the node won't start. `--list` shows what a package
//! would hold and writes nothing. The file is written owner-only (`0600`) and never overwrites one.

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Value, json};
use telltale_api::SupportPackageOutput;
use telltale_api::model::SupportPackageRequest;
use telltale_support::archive::read_tar_gz;

/// The command's options.
#[derive(Debug)]
pub(crate) struct Args {
    pub(crate) level: String,
    pub(crate) reveal: Vec<String>,
    pub(crate) query_sample: u32,
    pub(crate) keep_map: Option<PathBuf>,
    pub(crate) list: bool,
    pub(crate) output: Option<PathBuf>,
    pub(crate) offline: bool,
    /// REQ: OPS-011 (ADR-172) — every reachable node's part, in one package.
    pub(crate) cluster: bool,
}

/// How much to read of the node's answer (the cap is 20 MiB of content).
const MAX_ANSWER: u64 = 32 << 20;

fn say(text: &str) {
    let _ = writeln!(io::stdout().lock(), "{text}");
}

/// `n` bytes as `12 KiB`.
#[allow(clippy::cast_precision_loss)] // shown to one decimal
fn size(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 10 * 1024 * 1024 {
        format!("{} KiB", n.div_ceil(1024))
    } else {
        format!("{:.1} MiB", n as f64 / 1_048_576.0)
    }
}

/// `a, b`-style counts: `3 address, 1 mac`.
fn counts(v: Option<&Value>) -> String {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, n)| format!("{n} {k}"))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

/// What the manifest says, as a table and a total.
fn show_manifest(m: &Value) -> String {
    if m["kind"] == "cluster" {
        return show_cluster(m);
    }
    let mut rows = vec![vec![
        "FILE".to_owned(),
        "PART".to_owned(),
        "SIZE".to_owned(),
        "REPLACED OR REMOVED".to_owned(),
    ]];
    let mut total = 0u64;
    for f in m["files"].as_array().into_iter().flatten() {
        let bytes = f["bytes"].as_u64().unwrap_or(0);
        total += bytes;
        let status = f["status"].as_str().unwrap_or("ok");
        let note = f["note"].as_str().unwrap_or("");
        rows.push(vec![
            f["path"].as_str().unwrap_or("?").to_owned(),
            f["collector"].as_str().unwrap_or("").to_owned(),
            if status == "missing" {
                "-".to_owned()
            } else {
                size(bytes)
            },
            match status {
                "missing" => format!("missing: {note}"),
                "truncated" => format!("cut: {note}"),
                _ => counts(f.get("redactions")),
            },
        ]);
    }
    let widths: Vec<usize> = (0..4)
        .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for r in &rows {
        let line: Vec<String> = r
            .iter()
            .zip(&widths)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    let _ = write!(
        out,
        "\nLevel {}; {} before compression.",
        m["level"].as_str().unwrap_or("?"),
        size(total)
    );
    let all = counts(m.get("redactions"));
    if !all.is_empty() {
        let _ = write!(out, "\nReplaced or removed: {all}.");
    }
    for n in m["notes"].as_array().into_iter().flatten() {
        let _ = write!(out, "\n{}", n.as_str().unwrap_or(""));
    }
    out
}

/// Writes `bytes` to `path`, owner-only, refusing to replace a file.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            format!(
                "{} already exists: pick another name with -o, or remove it",
                path.display()
            )
        } else {
            format!("{}: {e}", path.display())
        }
    })?;
    f.write_all(bytes)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// REQ: OPS-011 (ADR-172) — what a cluster package holds: each node, whether it answered, how much.
fn show_cluster(m: &Value) -> String {
    let mut out = String::from("NODE  STATUS  FILES  SIZE  NOTE\n");
    for n in m["nodes"].as_array().into_iter().flatten() {
        let _ = writeln!(
            out,
            "{}  {}  {}  {}  {}",
            n["node"].as_str().unwrap_or("?"),
            n["status"].as_str().unwrap_or("?"),
            n["files"].as_u64().unwrap_or(0),
            size(n["bytes"].as_u64().unwrap_or(0)),
            n["note"].as_str().unwrap_or("")
        );
    }
    let _ = write!(
        out,
        "\nLevel {}; one part per node, each redacted on its own node.",
        m["level"].as_str().unwrap_or("?")
    );
    out
}

/// The package from a running node: `(file name, the map's ID, manifest, archive)`.
async fn ask_node(
    base: &str,
    ca: Option<&Path>,
    token: &str,
    req: &SupportPackageRequest,
    dry_run: bool,
) -> Result<(String, Option<String>, Value, Vec<u8>), String> {
    let client = crate::ctl::client(ca)?;
    let body = json!({
        "level": req.level,
        "reveal": req.reveal,
        "querySample": req.query_sample,
        "keepMap": req.keep_map,
        "cluster": req.cluster,
    });
    let url = format!(
        "{}/api/v1/system/support-package{}",
        base.trim_end_matches('/'),
        if dry_run { "?dryRun=true" } else { "" }
    );
    let http_req = http::Request::builder()
        .method(http::Method::POST)
        .uri(url.as_str())
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let resp = client
        .request(http_req, MAX_ANSWER)
        .await
        .map_err(|e| format!("can't reach {url}: {}", e.message))?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body();
    if !status.is_success() {
        return Err(problem(status.as_u16(), &bytes));
    }
    if dry_run {
        let m: Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("the node's answer: {e}"))?;
        return Ok((String::new(), None, m, Vec::new()));
    }
    let name = headers
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split("filename=\"").nth(1))
        .and_then(|v| v.split('"').next())
        .unwrap_or("telltale-support.tar.gz")
        .to_owned();
    let id = headers
        .get("x-support-package-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let manifest = read_tar_gz(&bytes)
        .and_then(|files| files.into_iter().find(|f| f.path == "MANIFEST.json"))
        .and_then(|f| serde_json::from_slice(&f.data).ok())
        .unwrap_or(Value::Null);
    Ok((name, id, manifest, bytes))
}

/// problem+json as one line: what's wrong, and the hint.
fn problem(status: u16, body: &[u8]) -> String {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let detail = v["detail"]
        .as_str()
        .or_else(|| v["title"].as_str())
        .unwrap_or("the request failed");
    let hint = v["hint"]
        .as_str()
        .map_or_else(String::new, |h| format!(" ({h})"));
    format!("HTTP {status}: {detail}{hint}")
}

/// The pseudonym map of the package just made, from the node.
async fn fetch_map(base: &str, ca: Option<&Path>, token: &str, id: &str) -> Result<String, String> {
    let client = crate::ctl::client(ca)?;
    let url = format!(
        "{}/api/v1/system/support-package/{id}/map",
        base.trim_end_matches('/')
    );
    let req = http::Request::builder()
        .uri(url.as_str())
        .header("authorization", format!("Bearer {token}"))
        .body(Vec::new())
        .map_err(|e| e.to_string())?;
    let resp = client
        .request(req, MAX_ANSWER)
        .await
        .map_err(|e| format!("can't reach {url}: {}", e.message))?;
    let status = resp.status();
    let bytes = resp.into_body();
    if status.is_success() {
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        Err(problem(status.as_u16(), &bytes))
    }
}

/// Runs the command.
pub(crate) fn run(
    a: &Args,
    url: Option<String>,
    ca_file: Option<PathBuf>,
    token_file: Option<&Path>,
    config: Vec<PathBuf>,
) -> ExitCode {
    let req = SupportPackageRequest {
        level: Some(a.level.clone()),
        reveal: a.reveal.clone(),
        query_sample: a.query_sample,
        keep_map: a.keep_map.is_some(),
        cluster: a.cluster,
    };
    if let Err(p) = telltale_api::support_api::validate(&req) {
        let hint = p
            .hint
            .as_deref()
            .map_or_else(String::new, |h| format!(" ({h})"));
        eprintln!("error: {}{hint}", p.detail);
        return ExitCode::from(2);
    }
    if a.cluster && a.offline {
        eprintln!("error: --cluster asks the running nodes, so it can't be made --offline");
        return ExitCode::from(2);
    }
    let token = match token_file {
        Some(p) => std::fs::read_to_string(p)
            .map(|t| Some(t.trim().to_owned()))
            .map_err(|e| format!("{}: {e}", p.display())),
        None => Ok(std::env::var("TELLTALE_TOKEN")
            .ok()
            .map(|t| t.trim().to_owned())),
    };
    let token = match token {
        Ok(t) => t.filter(|t| !t.is_empty()),
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let made = match (&token, a.offline) {
        (Some(t), false) => online(a, &req, url, ca_file, t, config),
        (None, false) => {
            eprintln!(
                "No API token (TELLTALE_TOKEN or --token-file): making an offline package from the configuration files and the logs. \
                 Give a token for one with the node's live state."
            );
            offline(&req, config)
        }
        (_, true) => offline(&req, config),
    };
    let (name, manifest, archive, map) = match made {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if a.list {
        say(&show_manifest(&manifest));
        say("\nNothing was written.");
        return ExitCode::SUCCESS;
    }
    let path = a.output.clone().unwrap_or_else(|| PathBuf::from(&name));
    if let Err(e) = write_new(&path, &archive) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    say(&format!(
        "Wrote {} ({}).",
        path.display(),
        size(archive.len() as u64)
    ));
    say(&show_manifest(&manifest));
    say(
        "\nLook it over before you attach it: log lines are redacted by pattern, which is best effort.",
    );
    if let (Some(file), Some(text)) = (&a.keep_map, map) {
        match write_new(file, text.as_bytes()) {
            Ok(()) => say(&format!(
                "The pseudonym map is in {}. It has your real names and addresses: keep it to yourself, don't attach it.",
                file.display()
            )),
            Err(e) => {
                eprintln!("error: the package is written, but the map isn't: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

type Made = (String, Value, Vec<u8>, Option<String>);

fn online(
    a: &Args,
    req: &SupportPackageRequest,
    url: Option<String>,
    ca_file: Option<PathBuf>,
    token: &str,
    config: Vec<PathBuf>,
) -> Result<Made, String> {
    let (base, ca) = crate::api_target(url, ca_file, config).map_err(|errs| {
        errs.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    })?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        let (name, id, manifest, archive) = ask_node(&base, ca.as_deref(), token, req, a.list)
            .await
            .map_err(|e| format!("{e}\nTo make a package from the files and logs without the node, add --offline."))?;
        let map = match (&id, a.keep_map.is_some()) {
            (Some(id), true) => Some(fetch_map(&base, ca.as_deref(), token, id).await?),
            _ => None,
        };
        Ok((name, manifest, archive, map))
    })
}

fn offline(req: &SupportPackageRequest, config: Vec<PathBuf>) -> Result<Made, String> {
    let files = crate::config_files(config);
    let loaded = files
        .iter()
        .fold(
            telltale_config::Loader::new(),
            telltale_config::Loader::file,
        )
        .process_env()
        .load()
        .map_err(|errs| {
            errs.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        })?;
    let (out, map) = crate::support::offline(&loaded.config, req).map_err(|p| p.detail)?;
    let SupportPackageOutput {
        file_name,
        manifest,
        archive,
        ..
    } = out;
    Ok((
        file_name,
        manifest,
        archive,
        (!map.is_empty()).then_some(map),
    ))
}
