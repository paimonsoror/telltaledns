//! Query-log search (`spec/06` §4 "Search"), newest first with a cursor:
//! 1. Segments by time, blocks by their headers (time range, status/RCODE masks, max
//!    latency) and, for an exact name or a client, by the block bloom over content hashes.
//!    A segment with no surviving block is skipped without reading anything else.
//! 2. Name and client predicates resolved against the segment dictionary first (millions
//!    of names in a 30-day search: matched in one reused buffer, no allocation per name).
//! 3. Per block, only the predicate columns are read, filtered column at a time into a
//!    selection vector; the other columns are read only for blocks with a match.

use std::io;
use std::path::Path;

use memchr::memmem;
use regex_automata::meta::Regex;
use regex_automata::util::syntax;
use telltale_telemetry::{Proto, Rule, RuleKind, Status};

use super::format::{self, BlockHeader, COLUMNS, Col};
use super::reader::{Columns, Dictionary, Segment};
use super::{SegmentId, list_segments};

/// How to match the query name (lowercase, no trailing dot).
#[derive(Debug, Clone)]
pub enum NameMatch {
    Exact(String),
    /// The name or any name below it.
    Suffix(String),
    Substring(String),
    /// `*` and `?` wildcards over the whole name.
    Glob(String),
    /// A regex over the whole name (linear-time engine: no backreferences or lookaround).
    Regex(String),
}

/// Which rows to return. Empty lists and `None` mean "any".
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Time range `[from_us, to_us)`; `to_us = 0` means "now and later".
    pub from_us: u64,
    pub to_us: u64,
    pub name: Option<NameMatch>,
    /// Client address (v4-mapped).
    pub client_ip: Option<[u8; 16]>,
    pub client_ref: Option<u32>,
    pub group: Option<u16>,
    pub status: Vec<Status>,
    pub qtype: Vec<u16>,
    pub rcode: Vec<u8>,
    pub upstream: Option<u16>,
    pub min_total_us: Option<u32>,
}

/// One logged query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub ts_us: u64,
    pub node: u16,
    pub client_ip: [u8; 16],
    pub client_ref: u32,
    pub group: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub rcode: Option<u8>,
    pub status: Status,
    pub proto: Proto,
    pub flags: u16,
    pub rule: Option<Rule>,
    pub upstream: u16,
    pub attempts: u8,
    pub t_total_us: u32,
    pub t_upstream_us: u32,
    pub resp_size: u16,
    pub answers: u16,
}

/// Where a page ended: continue strictly after (older than) this row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub segment: SegmentId,
    pub block: u32,
    pub row: u32,
}

impl Cursor {
    /// Opaque text form for APIs: `hour.node.part.block.row`.
    pub fn encode(&self) -> String {
        let s = self.segment;
        format!(
            "{}.{}.{}.{}.{}",
            s.hour, s.node, s.part, self.block, self.row
        )
    }

    pub fn decode(text: &str) -> Option<Self> {
        let mut it = text.split('.');
        let c = Self {
            segment: SegmentId {
                hour: it.next()?.parse().ok()?,
                node: it.next()?.parse().ok()?,
                part: it.next()?.parse().ok()?,
            },
            block: it.next()?.parse().ok()?,
            row: it.next()?.parse().ok()?,
        };
        it.next().is_none().then_some(c)
    }
}

/// What a search looked at (for cost reporting and tests).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchStats {
    pub segments: usize,
    pub blocks_total: usize,
    pub blocks_read: usize,
    pub rows_scanned: usize,
    /// Segments whose dictionary was read.
    pub dictionaries: usize,
}

/// A page of results.
#[derive(Debug, Clone, Default)]
pub struct Page {
    pub rows: Vec<Row>,
    /// Pass back to get the next (older) page; `None` when there is nothing older.
    pub next: Option<Cursor>,
    pub stats: SearchStats,
}

/// Compiled name predicate.
enum NamePred {
    /// Lowercase wire form, and its bloom key.
    Exact(Vec<u8>, u64),
    /// `.name` and `name`.
    Suffix(Vec<u8>, Vec<u8>),
    Substring(Box<memmem::Finder<'static>>),
    Regex(Regex),
}

impl NamePred {
    fn new(m: &NameMatch) -> io::Result<Self> {
        let norm = |s: &str| s.trim_end_matches('.').to_ascii_lowercase();
        Ok(match m {
            NameMatch::Exact(n) => {
                let wire = to_wire(&norm(n));
                let key = format::name_key(&wire);
                Self::Exact(wire, key)
            }
            NameMatch::Suffix(n) => {
                let n = norm(n);
                Self::Suffix(format!(".{n}").into_bytes(), n.into_bytes())
            }
            NameMatch::Substring(s) => Self::Substring(Box::new(
                memmem::Finder::new(s.to_ascii_lowercase().as_bytes()).into_owned(),
            )),
            NameMatch::Glob(g) => Self::Regex(compile(&glob_to_regex(&norm(g)))?),
            NameMatch::Regex(r) => Self::Regex(compile(r)?),
        })
    }

    /// Does dictionary name `wire` match? `dotted` is a scratch buffer.
    fn matches(&self, wire: &[u8], dotted: &mut Vec<u8>) -> bool {
        if let Self::Exact(w, _) = self {
            return wire == w.as_slice();
        }
        dotted_into(wire, dotted);
        match self {
            Self::Exact(..) => false,
            Self::Suffix(dot, bare) => {
                dotted.as_slice() == bare.as_slice() || dotted.ends_with(dot)
            }
            Self::Substring(f) => f.find(dotted).is_some(),
            Self::Regex(re) => re.is_match(dotted.as_slice()),
        }
    }

    fn bloom_key(&self) -> Option<u64> {
        match self {
            Self::Exact(_, key) => Some(*key),
            _ => None,
        }
    }
}

/// `ads.example.com` → wire format.
fn to_wire(dotted: &str) -> Vec<u8> {
    let mut w = Vec::with_capacity(dotted.len() + 2);
    for label in dotted.split('.').filter(|l| !l.is_empty()) {
        w.push(u8::try_from(label.len()).unwrap_or(0));
        w.extend_from_slice(label.as_bytes());
    }
    w.push(0);
    w
}

/// Wire format → dotted (no trailing dot), into a reused buffer.
fn dotted_into(wire: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let mut pos = 0;
    while let Some(&len) = wire.get(pos) {
        let len = usize::from(len);
        let Some(label) = wire.get(pos + 1..pos + 1 + len).filter(|_| len > 0) else {
            break;
        };
        if !out.is_empty() {
            out.push(b'.');
        }
        out.extend_from_slice(label);
        pos += 1 + len;
    }
}

fn compile(pattern: &str) -> io::Result<Regex> {
    Regex::builder()
        .syntax(syntax::Config::new().case_insensitive(true))
        .configure(Regex::config().nfa_size_limit(Some(4 << 20)))
        .build(pattern)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("name pattern: {e}")))
}

fn glob_to_regex(glob: &str) -> String {
    let mut re = String::from("^");
    for c in glob.chars() {
        match c {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c => {
                if "\\.+*?()|[]{}^$#&-~".contains(c) {
                    re.push('\\');
                }
                re.push(c);
            }
        }
    }
    re.push('$');
    re
}

/// Dictionary IDs that match a predicate (`None` = no predicate: every ID).
type IdSet = Option<Vec<bool>>;

fn contains(set: &IdSet, id: u64) -> bool {
    set.as_ref()
        .is_none_or(|v| usize::try_from(id).is_ok_and(|i| v.get(i).copied().unwrap_or(false)))
}

fn any(set: &IdSet) -> bool {
    set.as_ref().is_none_or(|v| v.iter().any(|&b| b))
}

/// Everything compiled from a [`Filter`] once per search.
struct Plan<'a> {
    f: &'a Filter,
    to_us: u64,
    name: Option<NamePred>,
    /// Bloom keys every candidate block must (maybe) contain.
    keys: Vec<u64>,
    /// Predicate columns besides time, name, and client.
    cols: Vec<Col>,
}

/// How a search runs.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Segments searched at once. Waves of this many segments run in parallel, newest
    /// first; results stay in order.
    pub threads: usize,
    /// Called at the start of every search thread (the server lowers its priority, so a
    /// search only uses CPU that DNS doesn't need).
    pub on_thread_start: Option<fn()>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            threads: 1,
            on_thread_start: None,
        }
    }
}

/// Searches `dir` (the `qlog` directory) newest first, on the calling thread.
pub fn search(dir: &Path, f: &Filter, limit: usize, cursor: Option<Cursor>) -> io::Result<Page> {
    search_with(dir, f, limit, cursor, &Options::default())
}

/// Searches `dir` newest first with `opts` (see [`Options`]).
// REQ: OBS-003
pub fn search_with(
    dir: &Path,
    f: &Filter,
    limit: usize,
    cursor: Option<Cursor>,
    opts: &Options,
) -> io::Result<Page> {
    let name = f.name.as_ref().map(NamePred::new).transpose()?;
    let mut keys: Vec<u64> = name
        .as_ref()
        .and_then(NamePred::bloom_key)
        .into_iter()
        .collect();
    keys.extend(f.client_ip.as_ref().map(format::client_key));
    let plan = Plan {
        f,
        to_us: if f.to_us == 0 { u64::MAX } else { f.to_us },
        name,
        keys,
        cols: predicate_columns(f),
    };
    let mut segments: Vec<(SegmentId, std::path::PathBuf)> = list_segments(dir)?
        .into_iter()
        .filter(|(id, _)| {
            // Rows can be up to an hour older than their segment's hour (late events).
            let seg_from = id.hour.saturating_sub(1) * 3_600_000_000;
            let seg_to = (id.hour + 1) * 3_600_000_000;
            cursor.is_none_or(|c| *id <= c.segment) && seg_to > f.from_us && seg_from < plan.to_us
        })
        .collect();
    segments.sort_by_key(|s| std::cmp::Reverse(s.0));
    let mut page = Page::default();
    if limit == 0 {
        return Ok(page);
    }
    let threads = opts.threads.max(1);
    if threads == 1 {
        let mut scratch = Scratch::default();
        for (id, path) in &segments {
            if one_segment(path, *id, &plan, limit, cursor, &mut page, &mut scratch)? {
                break;
            }
        }
        return Ok(page);
    }
    parallel(&segments, &plan, limit, cursor, opts, threads, page)
}

/// One worker's result for one segment: its rows (at most the room left when it started)
/// and their (block, row) positions.
type SegmentResult = io::Result<(Page, Vec<(usize, usize)>)>;

/// A pool of `threads` workers claims segments newest first; the calling thread merges
/// their results strictly in segment order and stops the pool as soon as the page is full,
/// so at most `threads` segments of work are wasted.
fn parallel(
    segments: &[(SegmentId, std::path::PathBuf)],
    plan: &Plan<'_>,
    limit: usize,
    cursor: Option<Cursor>,
    opts: &Options,
    threads: usize,
    mut page: Page,
) -> io::Result<Page> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex, PoisonError};
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let results: Mutex<Vec<Option<SegmentResult>>> =
        Mutex::new((0..segments.len()).map(|_| None).collect());
    let ready = Condvar::new();
    std::thread::scope(|sc| {
        for _ in 0..threads.min(segments.len()) {
            sc.spawn(|| {
                if let Some(init) = opts.on_thread_start {
                    init();
                }
                let mut scratch = Scratch::default();
                loop {
                    let k = next.fetch_add(1, Ordering::Relaxed);
                    if k >= segments.len() || stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let (id, path) = &segments[k];
                    let mut p = Page::default();
                    scratch.pos.clear();
                    // A panic must still fill the slot, or the merging thread would wait
                    // forever.
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        one_segment(path, *id, plan, limit, cursor, &mut p, &mut scratch)
                    }))
                    .unwrap_or_else(|_| Err(io::Error::other("search thread panicked")))
                    .map(|_| (p, std::mem::take(&mut scratch.pos)));
                    results.lock().unwrap_or_else(PoisonError::into_inner)[k] = Some(r);
                    ready.notify_all();
                }
            });
        }
        let outcome: io::Result<()> = (|| {
            for (k, (id, _)) in segments.iter().enumerate() {
                let result = {
                    let mut g = results.lock().unwrap_or_else(PoisonError::into_inner);
                    loop {
                        if let Some(r) = g[k].take() {
                            break r;
                        }
                        g = ready.wait(g).unwrap_or_else(PoisonError::into_inner);
                    }
                };
                let (p, pos) = result?;
                add_stats(&mut page.stats, &p.stats);
                let room = limit - page.rows.len();
                if p.rows.len() < room {
                    page.rows.extend(p.rows);
                    continue;
                }
                // This segment fills the page: keep `room` rows and continue right after the
                // last one (older rows in this segment, then older segments). Unlike the
                // sequential path we haven't looked further, so the next page may be empty.
                page.rows.extend(p.rows.into_iter().take(room));
                page.next = pos.get(room - 1).map(|&(block, row)| Cursor {
                    segment: *id,
                    block: u32::try_from(block).unwrap_or(u32::MAX),
                    row: u32::try_from(row).unwrap_or(u32::MAX),
                });
                return Ok(());
            }
            Ok(())
        })();
        stop.store(true, Ordering::Relaxed);
        outcome
    })?;
    Ok(page)
}
/// What a search would read at most, from segment and block headers only (no column is
/// read): the cost estimate of an analytics query (REQ: AGT-012).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Estimate {
    /// Segments and blocks a scan would read.
    pub segments: usize,
    pub blocks: usize,
    /// Rows in those blocks: an upper bound on the matches.
    pub rows: u64,
}

/// Estimates what searching `dir` with `f` would read (see [`Estimate`]).
pub fn estimate(dir: &Path, f: &Filter) -> io::Result<Estimate> {
    let name = f.name.as_ref().map(NamePred::new).transpose()?;
    let name_key = name.as_ref().and_then(NamePred::bloom_key);
    let mut keys: Vec<u64> = name_key.into_iter().collect();
    keys.extend(f.client_ip.as_ref().map(format::client_key));
    let to_us = if f.to_us == 0 { u64::MAX } else { f.to_us };
    let mut e = Estimate::default();
    for (id, path) in list_segments(dir)? {
        let seg_from = id.hour.saturating_sub(1) * 3_600_000_000;
        let seg_to = (id.hour + 1) * 3_600_000_000;
        if seg_to <= f.from_us || seg_from >= to_us {
            continue;
        }
        let Ok(seg) = Segment::open(&path) else {
            continue;
        };
        if let (Some(k), Some(names)) = (name_key, &seg.names)
            && !names.may_contain(k)
        {
            continue;
        }
        let before = e.blocks;
        for (_, h) in &seg.blocks {
            if block_may_match(h, f, to_us) && keys.iter().all(|&k| h.bloom_may_contain(k)) {
                e.blocks += 1;
                e.rows += u64::from(h.rows);
            }
        }
        if e.blocks > before {
            e.segments += 1;
        }
    }
    Ok(e)
}

fn add_stats(a: &mut SearchStats, b: &SearchStats) {
    a.segments += b.segments;
    a.blocks_total += b.blocks_total;
    a.blocks_read += b.blocks_read;
    a.rows_scanned += b.rows_scanned;
    a.dictionaries += b.dictionaries;
}

/// Opens and searches one segment; returns true when the page is full.
fn one_segment(
    path: &Path,
    id: SegmentId,
    plan: &Plan<'_>,
    limit: usize,
    cursor: Option<Cursor>,
    page: &mut Page,
    scratch: &mut Scratch,
) -> io::Result<bool> {
    let Ok(mut seg) = Segment::open(path) else {
        return Ok(false); // unreadable segment: skip, never fail the whole search
    };
    page.stats.segments += 1;
    page.stats.blocks_total += seg.blocks.len();
    search_segment(&mut seg, id, plan, limit, cursor, page, scratch)
}
/// Buffers reused across blocks and segments.
#[derive(Default)]
struct Scratch {
    sel: Vec<bool>,
    dotted: Vec<u8>,
    /// (block, row) of each row this worker returned, for cursors after a merge.
    pos: Vec<(usize, usize)>,
}

/// Searches one segment; returns true when the page is full.
fn search_segment(
    seg: &mut Segment,
    id: SegmentId,
    plan: &Plan<'_>,
    limit: usize,
    cursor: Option<Cursor>,
    page: &mut Page,
    s: &mut Scratch,
) -> io::Result<bool> {
    let f = plan.f;
    // A finished segment's name filter rules out an exact name without reading blocks.
    if let (Some(key), Some(filter)) =
        (plan.name.as_ref().and_then(NamePred::bloom_key), &seg.names)
        && !filter.may_contain(key)
    {
        return Ok(false);
    }
    let start_block = match cursor {
        Some(c) if c.segment == id => (c.block as usize + 1).min(seg.blocks.len()),
        _ => seg.blocks.len(),
    };
    let candidates: Vec<usize> = (0..start_block)
        .rev()
        .filter(|&i| {
            let h = &seg.blocks[i].1;
            block_may_match(h, f, plan.to_us) && plan.keys.iter().all(|&k| h.bloom_may_contain(k))
        })
        .collect();
    if candidates.is_empty() {
        return Ok(false);
    }
    // The dictionary is read only when a predicate needs it, or for the first match's name.
    let mut dict: Option<Dictionary> = None;
    let (mut names, mut clients): (IdSet, IdSet) = (None, None);
    if plan.name.is_some() || f.client_ip.is_some() {
        let d = seg.dictionary()?;
        page.stats.dictionaries += 1;
        names = plan
            .name
            .as_ref()
            .map(|p| d.names().map(|n| p.matches(n, &mut s.dotted)).collect());
        clients = f
            .client_ip
            .map(|ip| d.clients.iter().map(|c| *c == ip).collect());
        if !any(&names) || !any(&clients) {
            return Ok(false);
        }
        dict = Some(d);
    }
    for i in candidates {
        let (rows, min_ts, max_ts) = {
            let h = &seg.blocks[i].1;
            (h.rows as usize, h.min_ts, h.max_ts)
        };
        let end_row = match cursor {
            Some(c) if c.segment == id && c.block as usize == i => (c.row as usize).min(rows),
            _ => rows,
        };
        let mut cols = Columns::new(rows);
        page.stats.blocks_read += 1;
        page.stats.rows_scanned += end_row;
        let ids = (&names, &clients);
        if !select(
            seg,
            i,
            plan,
            ids,
            (min_ts, max_ts),
            end_row,
            &mut cols,
            &mut s.sel,
        )? {
            continue;
        }
        seg.load(i, &mut cols, &COLUMNS)?; // a match: now the rest of the row
        // The rows this page will take from the block (newest first).
        let room = limit - page.rows.len();
        let picked: Vec<usize> = (0..end_row)
            .rev()
            .filter(|&r| s.sel[r])
            .take(room + 1)
            .collect();
        // Names and clients for those rows: from the full dictionary if a predicate already
        // read it, else only the dictionary blocks that hold them.
        let lookup = if dict.is_none() {
            let ids = |col| picked.iter().map(|&r| cols.get(col, r)).collect::<Vec<_>>();
            Some(seg.lookup(&ids(Col::NameId), &ids(Col::ClientId))?)
        } else {
            None
        };
        let names = Names {
            dict: dict.as_ref(),
            lookup: lookup.as_ref(),
        };
        if push_rows(&picked, room, (id, i, min_ts), &cols, &names, page, s) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Where output rows get their names and clients.
struct Names<'a> {
    dict: Option<&'a Dictionary>,
    lookup: Option<&'a super::reader::Lookup>,
}

impl Names<'_> {
    fn get(&self, nid: u64, cid: u64) -> (Option<&[u8]>, Option<[u8; 16]>) {
        match (self.dict, self.lookup) {
            (Some(d), _) => (
                usize::try_from(nid).ok().and_then(|x| d.name(x)),
                usize::try_from(cid)
                    .ok()
                    .and_then(|x| d.clients.get(x))
                    .copied(),
            ),
            (None, Some(l)) => (
                l.names.get(&nid).map(|n| &n[..]),
                l.clients.get(&cid).copied(),
            ),
            (None, None) => (None, None),
        }
    }
}

/// Appends the picked rows (newest first) until the page is full; then sets the cursor at
/// the first row that didn't fit and returns true.
fn push_rows(
    picked: &[usize],
    room: usize,
    (id, block, min_ts): (SegmentId, usize, u64),
    cols: &Columns,
    names: &Names<'_>,
    page: &mut Page,
    s: &mut Scratch,
) -> bool {
    for (n, &r) in picked.iter().enumerate() {
        if n == room {
            page.next = Some(Cursor {
                segment: id,
                block: u32::try_from(block).unwrap_or(u32::MAX),
                row: u32::try_from(r + 1).unwrap_or(u32::MAX),
            });
            return true;
        }
        let (name, client) = names.get(cols.get(Col::NameId, r), cols.get(Col::ClientId, r));
        let ts = min_ts + cols.get(Col::Ts, r);
        page.rows.push(row(cols, r, ts, id.node, name, client));
        s.pos.push((block, r));
    }
    false
}

/// Fills `sel` (one flag per row below `end_row`) by filtering one predicate column at a
/// time. Returns whether any row survived.
#[allow(clippy::too_many_arguments)]
fn select(
    seg: &mut Segment,
    i: usize,
    plan: &Plan<'_>,
    (names, clients): (&IdSet, &IdSet),
    (min_ts, max_ts): (u64, u64),
    end_row: usize,
    cols: &mut Columns,
    sel: &mut Vec<bool>,
) -> io::Result<bool> {
    let f = plan.f;
    sel.clear();
    sel.resize(end_row, true);
    let mut keep = |seg: &mut Segment, cols: &mut Columns, col: Col, pred: &dyn Fn(u64) -> bool| {
        seg.load(i, cols, &[col])?;
        let mut alive = false;
        for (r, s) in sel.iter_mut().enumerate() {
            if *s {
                *s = pred(cols.get(col, r));
                alive |= *s;
            }
        }
        Ok::<bool, io::Error>(alive)
    };
    // Time only matters when the block straddles the range.
    if min_ts < f.from_us || max_ts >= plan.to_us {
        let range = f.from_us..plan.to_us;
        if !keep(seg, cols, Col::Ts, &|d| range.contains(&(min_ts + d)))? {
            return Ok(false);
        }
    }
    if names.is_some() && !keep(seg, cols, Col::NameId, &|v| contains(names, v))? {
        return Ok(false);
    }
    if clients.is_some() && !keep(seg, cols, Col::ClientId, &|v| contains(clients, v))? {
        return Ok(false);
    }
    let one = |v: Option<u64>| v.unwrap_or(0);
    for &col in &plan.cols {
        let alive = match col {
            Col::ClientRef => {
                let v = one(f.client_ref.map(u64::from));
                keep(seg, cols, col, &|x| x == v)?
            }
            Col::Group => {
                let v = one(f.group.map(u64::from));
                keep(seg, cols, col, &|x| x == v)?
            }
            Col::Upstream => {
                let v = one(f.upstream.map(u64::from));
                keep(seg, cols, col, &|x| x == v)?
            }
            Col::TotalUs => {
                let v = one(f.min_total_us.map(u64::from));
                keep(seg, cols, col, &|x| x >= v)?
            }
            Col::Status => keep(seg, cols, col, &|x| f.status.iter().any(|s| *s as u64 == x))?,
            Col::Qtype => keep(seg, cols, col, &|x| {
                f.qtype.iter().any(|&t| u64::from(t) == x)
            })?,
            Col::Rcode => keep(seg, cols, col, &|x| {
                f.rcode.iter().any(|&r| u64::from(r) == x)
            })?,
            _ => true,
        };
        if !alive {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Value columns that filters other than time, name, and client need, cheapest and most
/// selective first.
fn predicate_columns(f: &Filter) -> Vec<Col> {
    let mut v = Vec::new();
    let mut add = |on: bool, c: Col| {
        if on {
            v.push(c);
        }
    };
    add(f.client_ref.is_some(), Col::ClientRef);
    add(!f.qtype.is_empty(), Col::Qtype);
    add(!f.rcode.is_empty(), Col::Rcode);
    add(f.min_total_us.is_some(), Col::TotalUs);
    add(f.upstream.is_some(), Col::Upstream);
    add(!f.status.is_empty(), Col::Status);
    add(f.group.is_some(), Col::Group);
    v
}

fn block_may_match(h: &BlockHeader, f: &Filter, to_us: u64) -> bool {
    if h.rows == 0 || h.max_ts < f.from_us || h.min_ts >= to_us {
        return false;
    }
    if !f.status.is_empty()
        && !f
            .status
            .iter()
            .any(|s| h.status_mask & (1 << (*s as u32 & 31)) != 0)
    {
        return false;
    }
    if !f.rcode.is_empty()
        && !f
            .rcode
            .iter()
            .any(|&rc| h.rcode_mask & (1 << if rc < 16 { u32::from(rc) } else { 16 }) != 0)
    {
        return false;
    }
    f.min_total_us.is_none_or(|m| h.max_total_us >= m)
}

#[allow(clippy::cast_possible_truncation)] // columns were written from these widths
fn row(
    c: &Columns,
    r: usize,
    ts_us: u64,
    node: u16,
    name: Option<&[u8]>,
    client: Option<[u8; 16]>,
) -> Row {
    let name = name.map_or_else(String::new, telltale_telemetry::event::dotted);
    let client_ip = client.unwrap_or([0; 16]);
    let rcode = c.get(Col::Rcode, r) as u8;
    let list = c.get(Col::RuleList, r);
    let kind = c.get(Col::RuleKind, r) as u8;
    let rule_kind = match kind & 0x7F {
        1 => Some(RuleKind::Domain),
        2 => Some(RuleKind::Modifier),
        3 => Some(RuleKind::Regex),
        4 => Some(RuleKind::Cname),
        5 => Some(RuleKind::Quick),
        6 => Some(RuleKind::Schedule),
        7 => Some(RuleKind::AnswerIp),
        _ => None,
    };
    let rule = rule_kind.filter(|_| list > 0).map(|k| Rule {
        list: (list - 1) as u16,
        kind: k,
        allow: kind & 0x80 != 0,
    });
    Row {
        ts_us,
        node,
        client_ip,
        client_ref: c.get(Col::ClientRef, r) as u32,
        group: c.get(Col::Group, r) as u16,
        name,
        qtype: c.get(Col::Qtype, r) as u16,
        qclass: c.get(Col::Qclass, r) as u16,
        rcode: (rcode != u8::MAX).then_some(rcode),
        status: Status::from_u8(c.get(Col::Status, r) as u8).unwrap_or(Status::Dropped),
        proto: Proto::from_u8(c.get(Col::Proto, r) as u8).unwrap_or(Proto::Udp),
        flags: c.get(Col::Flags, r) as u16,
        rule,
        upstream: c.get(Col::Upstream, r) as u16,
        attempts: c.get(Col::Attempts, r) as u8,
        t_total_us: c.get(Col::TotalUs, r) as u32,
        t_upstream_us: c.get(Col::UpstreamUs, r) as u32,
        resp_size: c.get(Col::RespSize, r) as u16,
        answers: c.get(Col::Answers, r) as u16,
    }
}
