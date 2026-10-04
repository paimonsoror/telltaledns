//! Query-log write path (`spec/06` §4 "Write path").
//!
//! [`Builder`] runs on the telemetry aggregator thread: it interns names and clients into the
//! segment dictionary, applies the privacy level, and collects rows. It never compresses or
//! touches the disk. Full or aged blocks go through a bounded channel to the writer thread,
//! which encodes, compresses, checksums, appends, rotates segments, writes footers, and
//! enforces retention. If the channel is full (slow disk), the block is dropped and counted,
//! and the builder starts a fresh segment part, because later blocks must never reference
//! dictionary entries that only the dropped block introduced.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use telltale_telemetry::QueryEvent;

use super::format::{
    self, BLOCK_HEADER, BlockHeader, COLUMNS, Col, HEADER_LEN, MAX_ROWS, SegmentHeader,
};
use super::{retention, segment_path};

/// Dictionary entries per segment part (names and clients each); beyond that a new part
/// starts. Bounds the builder's memory under floods of unique names.
pub const MAX_DICT: usize = 1 << 16;
/// Blocks queued for the writer thread.
const QUEUE: usize = 8;

/// Query-log settings.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The `qlog` directory.
    pub dir: PathBuf,
    pub node: u16,
    /// 0 full; 1 hide domains; 2 hide domains and clients; 3 no per-query log.
    pub privacy: u8,
    /// Flush a block after this long even if it isn't full.
    pub flush_interval: Duration,
    pub fsync: bool,
    pub retention_days: u32,
    pub retention_bytes: u64,
}

/// Write-path counters (for `/metrics`).
#[derive(Debug, Default)]
pub struct Stats {
    pub rows_written: AtomicU64,
    pub rows_dropped: AtomicU64,
    pub blocks_written: AtomicU64,
    pub bytes_written: AtomicU64,
    pub segments_removed: AtomicU64,
    pub write_errors: AtomicU64,
    /// The last write error, for logs and status.
    pub last_error: Mutex<Option<String>>,
}

/// One row as the builder holds it.
#[derive(Debug, Clone, Copy)]
struct RowIn {
    ev: QueryEvent,
    name_id: u32,
    client_id: u32,
    /// Bloom keys of the stored name and client (computed once per dictionary entry).
    name_key: u64,
    client_key: u64,
}

/// Which segment part a block belongs to: hour plus a per-process sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PartKey {
    hour: u64,
    seq: u32,
}

/// A sealed block on its way to the writer thread.
#[derive(Debug)]
struct RawBlock {
    key: PartKey,
    rows: Vec<RowIn>,
    /// Dictionary entries introduced by this block, in ID order.
    new_names: Vec<Box<[u8]>>,
    new_clients: Vec<[u8; 16]>,
}

enum Msg {
    Block(RawBlock),
    /// Finish the current part (write its footer); sent on shutdown.
    Close,
}

/// The aggregator-side half: collects rows into blocks.
#[derive(Debug)]
pub struct Builder {
    settings: Settings,
    tx: Option<SyncSender<Msg>>,
    stats: Arc<Stats>,
    key: Option<PartKey>,
    next_seq: u32,
    /// Name → (ID, bloom key of the stored form).
    names: HashMap<Box<[u8]>, (u32, u64)>,
    clients: HashMap<[u8; 16], (u32, u64)>,
    rows: Vec<RowIn>,
    new_names: Vec<Box<[u8]>>,
    new_clients: Vec<[u8; 16]>,
    opened: Instant,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Builder {
    /// Starts the writer thread. With privacy level 3 nothing is ever written.
    pub fn spawn(settings: Settings) -> io::Result<Self> {
        let stats = Arc::new(Stats::default());
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        let (tx, thread) = if settings.privacy >= 3 {
            (None, None)
        } else {
            let (s, st) = (settings.clone(), Arc::clone(&stats));
            let t = std::thread::Builder::new()
                .name("telltale-qlog".into())
                .spawn(move || writer_loop(&s, &st, &rx))?;
            (Some(tx), Some(t))
        };
        Ok(Self {
            settings,
            tx,
            stats,
            key: None,
            next_seq: 0,
            names: HashMap::new(),
            clients: HashMap::new(),
            rows: Vec::with_capacity(MAX_ROWS),
            new_names: Vec::new(),
            new_clients: Vec::new(),
            opened: Instant::now(),
            thread,
        })
    }

    pub fn stats(&self) -> Arc<Stats> {
        Arc::clone(&self.stats)
    }

    /// Adds one query (REQ: OBS-003). `name` is the wire-format qname.
    pub fn push(&mut self, ev: &QueryEvent, name: &[u8]) {
        if self.tx.is_none() {
            return;
        }
        let hour = ev.ts_us / 3_600_000_000;
        match self.key {
            // A new hour starts a new segment; late events from an earlier hour stay in the
            // current one (search prunes by row time, not by file).
            Some(k) if hour > k.hour => self.rotate(hour),
            Some(_) => {}
            None => self.rotate(hour),
        }
        if self.names.len() >= MAX_DICT || self.clients.len() >= MAX_DICT {
            let h = self.key.map_or(hour, |k| k.hour);
            self.rotate(h);
        }
        let mut ev = *ev;
        let privacy = self.settings.privacy;
        if privacy >= 2 {
            ev.client_ip = [0; 16];
            ev.client_ref = 0;
        }
        let (name_id, name_key) = if let Some(&v) = self.names.get(name) {
            v
        } else {
            let id = u32::try_from(self.names.len()).unwrap_or(u32::MAX);
            let stored: Box<[u8]> = if privacy >= 1 {
                hidden_name(name)
            } else {
                name.into()
            };
            let key = format::name_key(&stored);
            self.names.insert(name.into(), (id, key));
            self.new_names.push(stored);
            (id, key)
        };
        let (client_id, client_key) = if let Some(&v) = self.clients.get(&ev.client_ip) {
            v
        } else {
            let id = u32::try_from(self.clients.len()).unwrap_or(u32::MAX);
            let key = format::client_key(&ev.client_ip);
            self.clients.insert(ev.client_ip, (id, key));
            self.new_clients.push(ev.client_ip);
            (id, key)
        };
        self.rows.push(RowIn {
            ev,
            name_id,
            client_id,
            name_key,
            client_key,
        });
        if self.rows.len() >= MAX_ROWS {
            self.seal();
        }
    }

    /// Flushes a block that has been open longer than the flush interval. Call regularly.
    pub fn tick(&mut self, now: Instant) {
        if !self.rows.is_empty() && now.duration_since(self.opened) >= self.settings.flush_interval
        {
            self.seal();
        }
    }

    /// Starts a new segment part with an empty dictionary.
    fn rotate(&mut self, hour: u64) {
        self.seal();
        self.key = Some(PartKey {
            hour,
            seq: self.next_seq,
        });
        self.next_seq = self.next_seq.wrapping_add(1);
        self.names.clear();
        self.clients.clear();
    }

    /// Hands the open block to the writer thread.
    fn seal(&mut self) {
        let (Some(key), Some(tx)) = (self.key, &self.tx) else {
            return;
        };
        if self.rows.is_empty() {
            return;
        }
        let rows = std::mem::replace(&mut self.rows, Vec::with_capacity(MAX_ROWS));
        let n = rows.len() as u64;
        let block = RawBlock {
            key,
            rows,
            new_names: std::mem::take(&mut self.new_names),
            new_clients: std::mem::take(&mut self.new_clients),
        };
        self.opened = Instant::now();
        match tx.try_send(Msg::Block(block)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.stats.rows_dropped.fetch_add(n, Ordering::Relaxed);
                // Later blocks may not reference names this block introduced.
                let hour = key.hour;
                self.key = None;
                self.rotate(hour);
            }
        }
    }
}

impl Drop for Builder {
    /// Flushes the open block and finishes the segment (footer) before the thread exits.
    fn drop(&mut self) {
        self.seal();
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Msg::Close);
            drop(tx);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl telltale_telemetry::ring::Sink for Builder {
    fn record(&mut self, r: &telltale_telemetry::event::Record) {
        if let telltale_telemetry::event::Record::Query(ev, name) = r {
            self.push(ev, name.as_wire());
        }
    }
    fn tick(&mut self, now: Instant) {
        Self::tick(self, now);
    }
}

/// Privacy level 1+: the name is replaced by a one-label hash, so the same name still groups
/// together but can't be read (`spec/06` §4 privacy levels).
pub fn hidden_name(name: &[u8]) -> Box<[u8]> {
    let h = blake3::hash(name);
    let mut label = String::from("h");
    for b in &h.as_bytes()[..8] {
        let _ = write!(label, "{b:02x}");
    }
    let mut wire = Vec::with_capacity(label.len() + 2);
    wire.push(u8::try_from(label.len()).unwrap_or(0));
    wire.extend_from_slice(label.as_bytes());
    wire.push(0);
    wire.into()
}

/// The open segment file on the writer thread.
struct Open {
    key: PartKey,
    path: PathBuf,
    file: File,
    len: u64,
    index: Vec<(u64, BlockHeader)>,
    /// Bloom keys of every name in the part, for the footer's name filter.
    name_keys: Vec<u64>,
}

fn writer_loop(s: &Settings, stats: &Stats, rx: &Receiver<Msg>) {
    let mut open: Option<Open> = None;
    let mut last_retention = Instant::now();
    run_retention(s, stats, None);
    loop {
        let msg = rx.recv_timeout(Duration::from_secs(60));
        let result = match msg {
            Ok(Msg::Block(b)) => write_block(s, stats, &mut open, &b),
            Ok(Msg::Close) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                let r = finish(&mut open, s.fsync);
                note(stats, r);
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(()),
        };
        note(stats, result);
        if last_retention.elapsed() >= Duration::from_secs(600) {
            run_retention(s, stats, open.as_ref().map(|o| o.path.as_path()));
            last_retention = Instant::now();
        }
    }
}

fn note(stats: &Stats, r: io::Result<()>) {
    if let Err(e) = r {
        stats.write_errors.fetch_add(1, Ordering::Relaxed);
        *stats
            .last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(e.to_string());
    }
}

fn run_retention(s: &Settings, stats: &Stats, current: Option<&Path>) {
    let now_hour = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 3600);
    match retention::enforce(
        &s.dir,
        now_hour,
        s.retention_days,
        s.retention_bytes,
        current,
    ) {
        Ok(n) => {
            stats
                .segments_removed
                .fetch_add(n as u64, Ordering::Relaxed);
        }
        Err(e) => note(stats, Err(e)),
    }
}

fn write_block(
    s: &Settings,
    stats: &Stats,
    open: &mut Option<Open>,
    b: &RawBlock,
) -> io::Result<()> {
    if open.as_ref().is_none_or(|o| o.key != b.key) {
        finish(open, s.fsync)?;
        *open = Some(create(s, b.key)?);
    }
    let Some(o) = open.as_mut() else {
        return Ok(());
    };
    let (header, body) = encode_block(b)?;
    let mut buf = Vec::with_capacity(BLOCK_HEADER + body.len());
    header.write(&mut buf);
    buf.extend_from_slice(&body);
    o.file.write_all(&buf)?;
    if s.fsync {
        o.file.sync_data()?;
    }
    o.index.push((o.len, header));
    o.len += buf.len() as u64;
    o.name_keys
        .extend(b.new_names.iter().map(|n| format::name_key(n)));
    stats
        .rows_written
        .fetch_add(b.rows.len() as u64, Ordering::Relaxed);
    stats.blocks_written.fetch_add(1, Ordering::Relaxed);
    stats
        .bytes_written
        .fetch_add(buf.len() as u64, Ordering::Relaxed);
    Ok(())
}

/// Creates the file for a new part: the first part number not on disk for this hour.
fn create(s: &Settings, key: PartKey) -> io::Result<Open> {
    let mut part = 0u32;
    let path = loop {
        let p = segment_path(&s.dir, key.hour, s.node, part);
        if !p.exists() {
            break p;
        }
        part += 1;
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)?;
    let mut head = Vec::with_capacity(HEADER_LEN);
    SegmentHeader {
        node: s.node,
        hour: key.hour,
        part,
    }
    .write(&mut head);
    file.write_all(&head)?;
    Ok(Open {
        key,
        path,
        file,
        len: HEADER_LEN as u64,
        index: Vec::new(),
        name_keys: Vec::new(),
    })
}

/// Writes the footer (block index) and closes the part.
fn finish(open: &mut Option<Open>, fsync: bool) -> io::Result<()> {
    let Some(mut o) = open.take() else {
        return Ok(());
    };
    let mut buf = Vec::new();
    let names = format::NameFilter::build(&o.name_keys);
    format::write_footer(&o.index, &names, &mut buf, o.len);
    o.file.write_all(&buf)?;
    if fsync {
        o.file.sync_all()?;
    }
    Ok(())
}

/// A complete segment (header, blocks, footer) in memory, with the same encoding as the
/// writer thread. For tests and the fuzzer's structure-aware mode; no threads, no files.
pub fn encode_in_memory(rows: &[(QueryEvent, Vec<u8>)], hour: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    SegmentHeader {
        node: 0,
        hour,
        part: 0,
    }
    .write(&mut out);
    let mut names: HashMap<Vec<u8>, (u32, u64)> = HashMap::new();
    let mut clients: HashMap<[u8; 16], (u32, u64)> = HashMap::new();
    let mut index = Vec::new();
    let mut keys = Vec::new();
    for chunk in rows.chunks(MAX_ROWS) {
        let mut block = RawBlock {
            key: PartKey { hour, seq: 0 },
            rows: Vec::with_capacity(chunk.len()),
            new_names: Vec::new(),
            new_clients: Vec::new(),
        };
        for (ev, name) in chunk {
            let next = u32::try_from(names.len()).unwrap_or(u32::MAX);
            let (name_id, name_key) = *names.entry(name.clone()).or_insert_with(|| {
                block.new_names.push(name.clone().into());
                (next, format::name_key(name))
            });
            let next = u32::try_from(clients.len()).unwrap_or(u32::MAX);
            let (client_id, client_key) = *clients.entry(ev.client_ip).or_insert_with(|| {
                block.new_clients.push(ev.client_ip);
                (next, format::client_key(&ev.client_ip))
            });
            block.rows.push(RowIn {
                ev: *ev,
                name_id,
                client_id,
                name_key,
                client_key,
            });
        }
        keys.extend(block.new_names.iter().map(|n| format::name_key(n)));
        let (h, body) = encode_block(&block)?;
        index.push((out.len() as u64, h.clone()));
        h.write(&mut out);
        out.extend_from_slice(&body);
    }
    let at = out.len() as u64;
    format::write_footer(&index, &format::NameFilter::build(&keys), &mut out, at);
    Ok(out)
}

/// Encodes a block: rows sorted by time, dictionary deltas, then one section per column.
fn encode_block(b: &RawBlock) -> io::Result<(BlockHeader, Vec<u8>)> {
    let mut rows = b.rows.clone();
    rows.sort_by_key(|r| r.ev.ts_us);
    let mut h = BlockHeader::empty();
    h.rows = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    h.new_names = u32::try_from(b.new_names.len()).unwrap_or(u32::MAX);
    h.new_clients = u32::try_from(b.new_clients.len()).unwrap_or(u32::MAX);
    for r in &rows {
        h.min_ts = h.min_ts.min(r.ev.ts_us);
        h.max_ts = h.max_ts.max(r.ev.ts_us);
        h.status_mask |= 1 << (r.ev.status as u32 & 31);
        h.rcode_mask |= 1
            << match r.ev.rcode {
                Some(rc) if rc < 16 => u32::from(rc),
                Some(_) => 16,
                None => 17,
            };
        h.max_total_us = h.max_total_us.max(r.ev.t_total_us);
        h.bloom_insert(r.name_key);
        h.bloom_insert(r.client_key);
    }
    let mut body = Vec::new();
    let mut raw = Vec::new();
    let mut k = 0;
    let mut add = |raw: &[u8], body: &mut Vec<u8>, h: &mut BlockHeader| -> io::Result<()> {
        let frame = format::deflate(raw)?;
        h.sections[k] = (
            u32::try_from(frame.len()).unwrap_or(u32::MAX),
            format::checksum(&frame),
        );
        k += 1;
        body.extend_from_slice(&frame);
        Ok(())
    };
    for n in &b.new_names {
        raw.push(u8::try_from(n.len()).unwrap_or(0));
        raw.extend_from_slice(n);
    }
    add(&raw, &mut body, &mut h)?;
    raw.clear();
    for c in &b.new_clients {
        raw.extend_from_slice(c);
    }
    add(&raw, &mut body, &mut h)?;
    for col in COLUMNS {
        raw.clear();
        for r in &rows {
            put(&mut raw, col, r, h.min_ts);
        }
        add(&raw, &mut body, &mut h)?;
    }
    h.body_len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    Ok((h, body))
}

fn put(out: &mut Vec<u8>, col: Col, r: &RowIn, min_ts: u64) {
    let e = &r.ev;
    let v: u64 = match col {
        Col::Ts => e.ts_us - min_ts,
        Col::NameId => u64::from(r.name_id),
        Col::ClientId => u64::from(r.client_id),
        Col::ClientRef => u64::from(e.client_ref),
        Col::Group => u64::from(e.group),
        Col::Qtype => u64::from(e.qtype),
        Col::Qclass => u64::from(e.qclass),
        Col::Rcode => u64::from(e.rcode.unwrap_or(u8::MAX)),
        Col::Status => e.status as u64,
        Col::Proto => e.proto as u64,
        Col::Flags => u64::from(e.flags),
        Col::RuleList => e.rule.map_or(0, |r| u64::from(r.list) + 1),
        Col::RuleKind => e.rule.map_or(0, |r| {
            u64::from(r.kind as u8 | if r.allow { 0x80 } else { 0 })
        }),
        Col::Upstream => u64::from(e.upstream),
        Col::Attempts => u64::from(e.attempts),
        Col::TotalUs => u64::from(e.t_total_us),
        Col::UpstreamUs => u64::from(e.t_upstream_us),
        Col::RespSize => u64::from(e.resp_size),
        Col::Answers => u64::from(e.answers),
    };
    if col.is_byte() {
        #[allow(clippy::cast_possible_truncation)] // byte columns hold u8 values
        out.push(v as u8);
    } else {
        format::put_varint(out, v);
    }
}
