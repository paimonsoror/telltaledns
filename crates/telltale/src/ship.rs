//! Query-log ship mode (REQ: CLU-007; T5.8, ADR-055): store-and-forward to another node.
//!
//! A node with `[telemetry] mode = "ship"` writes its query log as usual, but bounded to
//! `[telemetry.ship] buffer_bytes`, and closes a segment part at least every `interval_secs`.
//! [`run`] delivers closed parts, oldest first, to the target node (the primary by default)
//! over the cluster channel in chunks. It deletes each part only once the target has verified
//! and stored the whole file. While the target is unreachable, parts wait in the buffer, and
//! the oldest give way when it's full.
//!
//! The receiver keeps them unchanged (the same columnar files, so nothing is re-encoded)
//! under `<data_dir>/qlog-nodes/<node-id>/`, with its own retention. Its query-log search
//! includes them, labelled with the node they came from. Every row lives in exactly one place
//! (the sender's buffer until delivered, then the receiver), so federated reads never count
//! a row twice.
//!
//! None of this is on the query path: the shipper is a background task, and the receiver
//! runs on blocking threads (CLU-004).

use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use telltale_cluster::net::Cluster;
use telltale_store::qlog::{SegmentId, list_segments, retention, segment_path};
use tracing::{debug, info, warn};

/// The RPC that carries one chunk of a segment.
pub(crate) const KIND: &str = "qlog.put";
/// Bytes per chunk (well under the 1 MiB frame limit).
const CHUNK: usize = 512 * 1024;
/// Largest segment accepted (a part closes every few minutes; this is far beyond that).
const MAX_SEGMENT: u64 = 256 << 20;
/// How often the shipper looks for closed parts.
const EVERY: Duration = Duration::from_secs(15);
/// How long one chunk may take.
const CHUNK_DEADLINE: Duration = Duration::from_secs(30);

/// REQ: CLU-007 (T9.3) — the RPC that carries a node's recent per-minute counts.
pub(crate) const ROLLUP_KIND: &str = "rollup.put";
/// Minutes re-sent each time (covers late events and a target that was briefly away).
const ROLLUP_WINDOW_S: u64 = 30 * 60;

/// `[start u64][len u32][encoded Counts]...`, big-endian.
fn encode_minutes(rows: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (start, data) in rows {
        out.extend_from_slice(&start.to_be_bytes());
        out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

fn decode_minutes(mut b: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let mut rows = Vec::new();
    while !b.is_empty() {
        let start = b
            .get(..8)
            .and_then(|x| <[u8; 8]>::try_from(x).ok())
            .map(u64::from_be_bytes);
        let len = b
            .get(8..12)
            .and_then(|x| <[u8; 4]>::try_from(x).ok())
            .map(u32::from_be_bytes);
        let (Some(start), Some(len)) = (start, len) else {
            return Err("short minute".into());
        };
        let len = usize::try_from(len).map_err(|e| e.to_string())?;
        let data = b.get(12..12 + len).ok_or("short minute data")?;
        rows.push((start, data.to_vec()));
        b = &b[12 + len..];
        if rows.len() > 2 * 1440 {
            return Err("too many minutes".into());
        }
    }
    Ok(rows)
}

/// Stores minutes `peer` (its mTLS node ID) sent (T9.3).
pub(crate) fn receive_rollups(
    db: &telltale_store::rollup::Rollups,
    peer: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    if !valid_node_id(peer) {
        return Err("bad node ID".into());
    }
    let rows = decode_minutes(body)?;
    db.put_shipped(peer, &rows).map_err(|e| e.to_string())?;
    Ok(b"ok".to_vec())
}

/// REQ: CLU-007 (T9.3) — a node in ship mode sends its recent per-minute counts to the same
/// target as its query log, so the dashboard keeps them after the node is gone (an
/// ephemeral pod restarts with an empty volume).
pub(crate) async fn run_rollups(
    cluster: Arc<Cluster>,
    db: Arc<telltale_store::rollup::Rollups>,
    to: Option<String>,
    every: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(every) => {}
            r = stop.changed() => if r.is_err() || *stop.borrow() { return; },
        }
        let me = cluster.identity.meta.node_id.clone();
        let Some(t) = target(&cluster, to.as_deref()).filter(|t| *t != me) else {
            continue;
        };
        let now = now_s();
        let d = Arc::clone(&db);
        let rows = tokio::task::spawn_blocking(move || {
            d.range(
                telltale_store::rollup::Level::Minute,
                now.saturating_sub(ROLLUP_WINDOW_S),
                now,
            )
        })
        .await;
        let Ok(Ok(rows)) = rows else { continue };
        if rows.is_empty() {
            continue;
        }
        let rows: Vec<(u64, Vec<u8>)> = rows
            .iter()
            .map(|(s, c)| (*s, telltale_store::rollup::encode(c)))
            .collect();
        if let Err(e) = cluster
            .call(&t, ROLLUP_KIND, encode_minutes(&rows), CHUNK_DEADLINE)
            .await
        {
            debug!("rollup shipping: {e}");
        }
    }
}

/// Where a node keeps the query logs others ship to it.
pub(crate) fn shipped_root(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("qlog-nodes")
}

/// Shipped query logs present here: `(source node ID, its directory)`.
pub(crate) fn shipped_dirs(data_dir: &str) -> Vec<(String, PathBuf)> {
    let Ok(rd) = std::fs::read_dir(shipped_root(data_dir)) else {
        return Vec::new();
    };
    let mut v: Vec<(String, PathBuf)> = rd
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .filter_map(|e| Some((e.file_name().to_str()?.to_owned(), e.path())))
        .filter(|(id, _)| valid_node_id(id))
        .collect();
    v.sort();
    v
}

/// Node IDs are lowercase hex; anything else never becomes a path.
fn valid_node_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Shipping counters (for `/metrics`).
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) segments_shipped: AtomicU64,
    pub(crate) bytes_shipped: AtomicU64,
    pub(crate) errors: AtomicU64,
    /// Closed parts waiting to be delivered.
    pub(crate) pending: AtomicU64,
    pub(crate) segments_received: AtomicU64,
    pub(crate) last_error: Mutex<Option<String>>,
}

/// One chunk's description; the chunk's bytes follow it in the RPC body.
#[derive(Debug, Serialize, Deserialize)]
struct Chunk {
    hour: u64,
    node: u16,
    part: u32,
    offset: u64,
    total: u64,
    /// BLAKE3 of the whole file, hex.
    hash: String,
}

fn encode(c: &Chunk, data: &[u8]) -> Vec<u8> {
    let head = serde_json::to_vec(c).unwrap_or_default();
    let mut out = Vec::with_capacity(4 + head.len() + data.len());
    out.extend_from_slice(&u32::try_from(head.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&head);
    out.extend_from_slice(data);
    out
}

fn decode(body: &[u8]) -> Result<(Chunk, &[u8]), String> {
    let len = body
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .ok_or("short chunk")?;
    let len = usize::try_from(len).map_err(|e| e.to_string())?;
    let head = body.get(4..4 + len).ok_or("short chunk header")?;
    let c: Chunk = serde_json::from_slice(head).map_err(|e| format!("bad chunk header: {e}"))?;
    Ok((c, &body[4 + len..]))
}

/// Stores one chunk from `peer` (its mTLS node ID). Answers `done` once the whole file is
/// verified and in place, `more` before that.
pub(crate) fn receive(
    data_dir: &str,
    peer: &str,
    body: &[u8],
    retention_days: u32,
    retention_bytes: u64,
    stats: &Stats,
) -> Result<Vec<u8>, String> {
    if !valid_node_id(peer) {
        return Err("unexpected node ID".into());
    }
    let (c, data) = decode(body)?;
    if c.total > MAX_SEGMENT || c.offset + data.len() as u64 > c.total {
        return Err(format!(
            "segment too large or chunk out of range ({} bytes)",
            c.total
        ));
    }
    let dir = shipped_root(data_dir).join(peer);
    let incoming = dir.join(".incoming");
    std::fs::create_dir_all(&incoming).map_err(|e| e.to_string())?;
    let tmp = incoming.join(format!("{}-{}-{}.seg.part", c.hour, c.node, c.part));
    let io = |e: io::Error| e.to_string();
    let mut f = if c.offset == 0 {
        std::fs::File::create(&tmp).map_err(io)?
    } else {
        let f = std::fs::OpenOptions::new()
            .append(true)
            .open(&tmp)
            .map_err(io)?;
        let have = f.metadata().map_err(io)?.len();
        if have != c.offset {
            return Err(format!("expected offset {have}, got {}", c.offset));
        }
        f
    };
    f.write_all(data).map_err(io)?;
    if c.offset + (data.len() as u64) < c.total {
        return Ok(b"more".to_vec());
    }
    f.sync_all().map_err(io)?;
    drop(f);
    let mut bytes = Vec::new();
    std::fs::File::open(&tmp)
        .and_then(|mut f| f.read_to_end(&mut bytes))
        .map_err(io)?;
    if blake3::hash(&bytes).to_hex().as_str() != c.hash {
        let _ = std::fs::remove_file(&tmp);
        return Err("checksum mismatch; resend".into());
    }
    let dest = segment_path(&dir, c.hour, c.node, c.part);
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p).map_err(io)?;
    }
    std::fs::rename(&tmp, &dest).map_err(io)?;
    stats.segments_received.fetch_add(1, Ordering::Relaxed);
    let now_hour = now_s() / 3600;
    if let Err(e) = retention::enforce(&dir, now_hour, retention_days, retention_bytes, None) {
        warn!(node = peer, "shipped query log retention: {e}");
    }
    Ok(b"done".to_vec())
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The node this node ships to: `to` (a node ID or site) or the primary, if reachable.
fn target(cluster: &Cluster, to: Option<&str>) -> Option<String> {
    match to {
        None => cluster.reachable_primary(),
        Some(t) => {
            let reachable = cluster.reachable_peers();
            cluster
                .members()
                .into_iter()
                .find(|m| (m.node_id == t || m.site == t) && reachable.contains(&m.node_id))
                .map(|m| m.node_id)
        }
    }
}

/// Closed parts, oldest first: every segment except the newest (the one being written).
fn closed(qlog: &Path) -> Vec<(SegmentId, PathBuf)> {
    let mut segs = list_segments(qlog).unwrap_or_default();
    segs.sort_by_key(|(id, _)| *id);
    segs.pop();
    segs
}

/// Delivers one segment; `Ok` once the receiver has it all.
async fn ship_one(cluster: &Cluster, to: &str, id: SegmentId, path: &Path) -> Result<u64, String> {
    let p = path.to_owned();
    let bytes = tokio::task::spawn_blocking(move || std::fs::read(p))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let total = bytes.len() as u64;
    if total > MAX_SEGMENT {
        return Err(format!(
            "{} is too large to ship ({total} bytes)",
            path.display()
        ));
    }
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let mut offset = 0usize;
    loop {
        let end = (offset + CHUNK).min(bytes.len());
        let c = Chunk {
            hour: id.hour,
            node: id.node,
            part: id.part,
            offset: offset as u64,
            total,
            hash: hash.clone(),
        };
        let reply = cluster
            .call(to, KIND, encode(&c, &bytes[offset..end]), CHUNK_DEADLINE)
            .await?;
        if reply == b"done" {
            return Ok(total);
        }
        if end >= bytes.len() {
            return Err("the receiver didn't confirm the whole file".into());
        }
        offset = end;
    }
}

/// Deletes a delivered part and the date directories it leaves empty.
fn remove(qlog: &Path, path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        warn!("couldn't remove shipped segment {}: {e}", path.display());
        return;
    }
    let mut d = path.parent();
    for _ in 0..3 {
        let Some(p) = d else { break };
        if p == qlog || std::fs::remove_dir(p).is_err() {
            break;
        }
        d = p.parent();
    }
}

/// The shipper: until `stop`, delivers closed parts of `qlog` to the target.
pub(crate) async fn run(
    cluster: Arc<Cluster>,
    qlog: PathBuf,
    to: Option<String>,
    stats: Arc<Stats>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    info!(
        to = to.as_deref().unwrap_or("the primary"),
        "query log ship mode: delivering closed parts"
    );
    let mut said_self = false;
    loop {
        let parts = closed(&qlog);
        stats.pending.store(parts.len() as u64, Ordering::Relaxed);
        let me = cluster.identity.meta.node_id.clone();
        match target(&cluster, to.as_deref()) {
            _ if parts.is_empty() => {}
            None if to.is_none() && cluster.is_primary() => {
                if !said_self {
                    info!(
                        "this node is the primary: its query log stays here (ship mode has no other target)"
                    );
                    said_self = true;
                }
            }
            None => debug!(
                "query log target unreachable; {} parts buffered",
                parts.len()
            ),
            Some(t) if t == me => {}
            Some(t) => {
                for (id, path) in parts {
                    match ship_one(&cluster, &t, id, &path).await {
                        Ok(n) => {
                            remove(&qlog, &path);
                            stats.segments_shipped.fetch_add(1, Ordering::Relaxed);
                            stats.bytes_shipped.fetch_add(n, Ordering::Relaxed);
                            stats.pending.fetch_sub(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                            debug!("query log shipping paused: {e}");
                            *stats
                                .last_error
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner) = Some(e);
                            break;
                        }
                    }
                }
            }
        }
        tokio::select! {
            () = tokio::time::sleep(EVERY) => {}
            r = stop.changed() => if r.is_err() || *stop.borrow() { return; },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-007 — a segment arrives in chunks, is verified, and lands under the sender's
    // node ID; a bad checksum or a hostile node ID never lands.
    #[test]
    fn clu_007_receiver_assembles_verifies_and_files_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let dd = tmp.path().to_str().unwrap();
        let stats = Stats::default();
        let file: Vec<u8> = (0..(CHUNK + 1000))
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let hash = blake3::hash(&file).to_hex().to_string();
        let chunk = |offset: usize, end: usize, hash: &str| {
            encode(
                &Chunk {
                    hour: now_s() / 3600,
                    node: 0,
                    part: 3,
                    offset: offset as u64,
                    total: file.len() as u64,
                    hash: hash.into(),
                },
                &file[offset..end],
            )
        };
        let put = |b: &[u8]| receive(dd, "abc123", b, 30, u64::MAX, &stats);
        assert_eq!(put(&chunk(0, CHUNK, &hash)).unwrap(), b"more");
        assert!(put(&chunk(10, 20, &hash)).is_err(), "out-of-order chunk");
        assert_eq!(put(&chunk(CHUNK, file.len(), &hash)).unwrap(), b"done");
        let dirs = shipped_dirs(dd);
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].0, "abc123");
        let stored = std::fs::read(segment_path(&dirs[0].1, now_s() / 3600, 0, 3)).unwrap();
        assert_eq!(stored, file);
        // Wrong hash: refused, nothing filed.
        assert_eq!(put(&chunk(0, CHUNK, "00")).unwrap(), b"more");
        assert!(
            put(&chunk(CHUNK, file.len(), "00"))
                .unwrap_err()
                .contains("checksum")
        );
        assert!(receive(dd, "../etc", &chunk(0, 10, &hash), 30, u64::MAX, &stats).is_err());
        assert_eq!(stats.segments_received.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn clu_007_only_closed_parts_ship() {
        let tmp = tempfile::tempdir().unwrap();
        for part in 0..3 {
            let p = segment_path(tmp.path(), 490_000, 0, part);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"x").unwrap();
        }
        let c = closed(tmp.path());
        assert_eq!(
            c.iter().map(|(id, _)| id.part).collect::<Vec<_>>(),
            [0, 1],
            "the newest is still being written"
        );
    }

    /// REQ: CLU-007 (T9.3) — minutes survive the trip and land per node; damaged bodies
    /// are refused.
    #[test]
    fn clu_007_rollup_minutes_ship() {
        let db = telltale_store::rollup::Rollups::in_memory().unwrap();
        let c = telltale_telemetry::agg::Counts {
            total: 7,
            ..Default::default()
        };
        let rows = vec![
            (600, telltale_store::rollup::encode(&c)),
            (660, telltale_store::rollup::encode(&c)),
        ];
        let body = encode_minutes(&rows);
        assert_eq!(receive_rollups(&db, "abc123", &body).unwrap(), b"ok");
        assert!(receive_rollups(&db, "abc123", &body[..body.len() - 1]).is_err());
        assert!(receive_rollups(&db, "../etc", &body).is_err());
        let got = db.shipped_range(0, 10_000, &[]).unwrap();
        assert_eq!(
            got.iter().map(|(s, c)| (*s, c.total)).collect::<Vec<_>>(),
            vec![(600, 7), (660, 7)]
        );
        assert!(
            db.shipped_range(0, 10_000, &["abc123".to_owned()])
                .unwrap()
                .is_empty(),
            "a live node isn't counted twice"
        );
    }
}
