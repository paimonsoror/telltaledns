//! Reading segments: headers via the footer or by walking blocks; then only the sections a
//! search needs (one positional read for one column, one for several), each checked
//! against its checksum before it's decompressed. Every length is checked before it's
//! trusted, and a corrupt or truncated tail just ends the segment (fuzzed:
//! `fuzz/fuzz_targets/qlog_segment.rs`).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::format::{
    self, BLOCK_HEADER, BlockHeader, COLUMNS, Col, HEADER_LEN, INDEX_ENTRY, MAX_BODY, MAX_ROWS,
    NameFilter, Reader, SegmentHeader, TRAILER,
};

/// Largest decompressed section (a column of 8192 ten-byte varints is 80 KiB; dictionary
/// sections hold at most 8192 names of 256 bytes).
const MAX_SECTION: usize = MAX_ROWS * 256;

/// An open segment: its header and block index.
#[derive(Debug)]
pub struct Segment {
    pub path: PathBuf,
    pub header: SegmentHeader,
    /// `(offset of the block header, header)`, in file order.
    pub blocks: Vec<(u64, BlockHeader)>,
    /// Every name in the segment (finished segments only).
    pub names: Option<NameFilter>,
    file: File,
}

/// A segment's dictionary: names (wire format) and clients, by ID. The decompressed name
/// sections are kept as they are (`len name len name ...`) in one buffer and indexed in
/// place: no allocation or copy per name (a 30-day search walks millions of them).
#[derive(Debug, Default)]
pub struct Dictionary {
    buf: Vec<u8>,
    /// Offset of each name's bytes in `buf`; its length is the byte before.
    starts: Vec<u32>,
    pub clients: Vec<[u8; 16]>,
}

impl Dictionary {
    pub fn name_count(&self) -> usize {
        self.starts.len()
    }

    /// Wire-format name `i`.
    pub fn name(&self, i: usize) -> Option<&[u8]> {
        let start = *self.starts.get(i)? as usize;
        let len = usize::from(*self.buf.get(start.checked_sub(1)?)?);
        self.buf.get(start..start + len)
    }

    /// Every name in ID order.
    pub fn names(&self) -> impl Iterator<Item = &[u8]> {
        (0..self.starts.len()).filter_map(|i| self.name(i))
    }

    /// Appends a compressed name section holding `count` names.
    fn add_names(&mut self, frame: &[u8], count: u32) -> io::Result<()> {
        let from = self.buf.len();
        let n = format::inflate_into(frame, MAX_SECTION, &mut self.buf)
            .ok_or_else(|| invalid("name dictionary"))?;
        let mut pos = from;
        for _ in 0..count {
            let len = usize::from(*self.buf.get(pos).ok_or_else(|| invalid("name length"))?);
            if pos + 1 + len > from + n {
                return Err(invalid("name bytes"));
            }
            self.starts
                .push(u32::try_from(pos + 1).map_err(|_| invalid("dictionary size"))?);
            pos += 1 + len;
        }
        Ok(())
    }
}

/// Names and clients by ID, for the rows being returned.
#[derive(Debug, Default)]
pub struct Lookup {
    pub names: std::collections::HashMap<u64, Box<[u8]>>,
    pub clients: std::collections::HashMap<u64, [u8; 16]>,
}

/// A block's decoded columns (only those asked for are filled).
#[derive(Debug, Default)]
pub struct Columns {
    pub rows: usize,
    cols: [Option<Vec<u64>>; COLUMNS.len()],
}

impl Columns {
    pub fn new(rows: usize) -> Self {
        Self {
            rows,
            ..Self::default()
        }
    }

    pub fn has(&self, col: Col) -> bool {
        self.cols[col as usize].is_some()
    }

    /// Decodes column `col` from its (already verified) compressed frame.
    pub fn decode(&mut self, col: Col, frame: &[u8]) -> io::Result<()> {
        let raw = format::inflate(frame, MAX_SECTION).ok_or_else(|| invalid("column data"))?;
        if raw.len() > self.rows * 10 {
            return Err(invalid("column length"));
        }
        let mut v = Vec::with_capacity(self.rows);
        if col.is_byte() {
            if raw.len() != self.rows {
                return Err(invalid("column length"));
            }
            v.extend(raw.iter().map(|&b| u64::from(b)));
        } else {
            let mut r = Reader::new(&raw);
            for _ in 0..self.rows {
                v.push(r.varint().ok_or_else(|| invalid("column varint"))?);
            }
        }
        self.cols[col as usize] = Some(v);
        Ok(())
    }

    /// Value of `col` at `row` (0 if the column wasn't decoded).
    pub fn get(&self, col: Col, row: usize) -> u64 {
        self.cols[col as usize]
            .as_ref()
            .and_then(|c| c.get(row))
            .copied()
            .unwrap_or(0)
    }
}

impl Segment {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        let mut head = [0u8; HEADER_LEN];
        file.read_exact(&mut head)?;
        let header =
            SegmentHeader::read(&head).ok_or_else(|| invalid("not a query-log segment"))?;
        let (blocks, names) = match read_footer(&mut file, len)? {
            Some((b, n)) => (b, Some(n)),
            None => (walk_blocks(&mut file, len)?, None),
        };
        Ok(Self {
            path: path.to_owned(),
            header,
            blocks,
            names,
            file,
        })
    }

    /// Parses a segment held in memory (tests and fuzzing): same checks as files.
    pub fn parse(bytes: &[u8]) -> Option<(SegmentHeader, Vec<(u64, BlockHeader)>)> {
        let header = SegmentHeader::read(bytes)?;
        let len = bytes.len() as u64;
        let mut cur = io::Cursor::new(bytes);
        let blocks = match read_footer(&mut cur, len).ok()? {
            Some((b, _)) => b,
            None => walk_blocks(&mut cur, len).ok()?,
        };
        Some((header, blocks))
    }

    /// The whole dictionary, from each block's two dictionary sections (one read per block).
    pub fn dictionary(&mut self) -> io::Result<Dictionary> {
        let mut d = Dictionary::default();
        for i in 0..self.blocks.len() {
            self.add_block_dictionary(i, &mut d)?;
        }
        Ok(d)
    }

    /// Adds block `i`'s dictionary delta to `d`.
    fn add_block_dictionary(&mut self, i: usize, d: &mut Dictionary) -> io::Result<()> {
        let (r0, r1) = {
            let h = &self.blocks[i].1;
            (h.section_range(0), h.section_range(1))
        };
        let bytes = self.read_body_range(i, r0.start..r1.end)?;
        let h = &self.blocks[i].1;
        let names = verified(h, 0, &bytes[..r0.len()])?;
        let clients = verified(h, 1, &bytes[r0.len()..])?;
        add_dictionary(d, h, names, clients)
    }

    /// Names and clients for specific IDs, decoding only the blocks that introduced them
    /// (rendering a few rows shouldn't decode a whole hour's dictionary).
    pub fn lookup(&mut self, name_ids: &[u64], client_ids: &[u64]) -> io::Result<Lookup> {
        let mut first_name = Vec::with_capacity(self.blocks.len() + 1);
        let mut first_client = Vec::with_capacity(self.blocks.len() + 1);
        let (mut n, mut c) = (0u64, 0u64);
        for (_, h) in &self.blocks {
            first_name.push(n);
            first_client.push(c);
            n += u64::from(h.new_names);
            c += u64::from(h.new_clients);
        }
        let block_of = |starts: &[u64], total: u64, id: u64| {
            (id < total).then(|| starts.partition_point(|&s| s <= id) - 1)
        };
        let mut needed: Vec<usize> = name_ids
            .iter()
            .filter_map(|&id| block_of(&first_name, n, id))
            .chain(
                client_ids
                    .iter()
                    .filter_map(|&id| block_of(&first_client, c, id)),
            )
            .collect();
        needed.sort_unstable();
        needed.dedup();
        let mut out = Lookup::default();
        for b in needed {
            let mut d = Dictionary::default();
            self.add_block_dictionary(b, &mut d)?;
            for &id in name_ids {
                if block_of(&first_name, n, id) == Some(b) {
                    let local = usize::try_from(id - first_name[b]).unwrap_or(usize::MAX);
                    if let Some(name) = d.name(local) {
                        out.names.insert(id, name.into());
                    }
                }
            }
            for &id in client_ids {
                if block_of(&first_client, c, id) == Some(b) {
                    let local = usize::try_from(id - first_client[b]).unwrap_or(usize::MAX);
                    if let Some(ip) = d.clients.get(local) {
                        out.clients.insert(id, *ip);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Decodes the columns in `want` that `cols` doesn't have yet, reading only those
    /// sections of block `i`.
    pub fn load(&mut self, i: usize, cols: &mut Columns, want: &[Col]) -> io::Result<()> {
        let missing: Vec<Col> = want.iter().copied().filter(|&c| !cols.has(c)).collect();
        if missing.len() > 2 {
            // Several columns: one read covering all of them instead of one each.
            let (lo, hi) = {
                let h = &self.blocks[i].1;
                let lo = missing
                    .iter()
                    .map(|c| h.section_range(c.section()).start)
                    .min();
                let hi = missing
                    .iter()
                    .map(|c| h.section_range(c.section()).end)
                    .max();
                (lo.unwrap_or(0), hi.unwrap_or(0))
            };
            let bytes = self.read_body_range(i, lo..hi)?;
            let h = &self.blocks[i].1;
            for col in missing {
                let r = h.section_range(col.section());
                let frame = verified(h, col.section(), &bytes[r.start - lo..r.end - lo])?;
                cols.decode(col, frame)?;
            }
            return Ok(());
        }
        for col in missing {
            let k = col.section();
            let range = self.blocks[i].1.section_range(k);
            let frame = self.read_body_range(i, range)?;
            cols.decode(col, verified(&self.blocks[i].1, k, &frame)?)?;
        }
        Ok(())
    }

    fn read_body_range(&mut self, i: usize, r: std::ops::Range<usize>) -> io::Result<Vec<u8>> {
        let off = self.blocks[i].0 + BLOCK_HEADER as u64 + r.start as u64;
        let mut buf = vec![0u8; r.len()];
        self.file.seek(SeekFrom::Start(off))?;
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// Checks section `k`'s frame against its checksum.
fn verified<'a>(h: &BlockHeader, k: usize, frame: &'a [u8]) -> io::Result<&'a [u8]> {
    if format::checksum(frame) == h.sections[k].1 {
        Ok(frame)
    } else {
        Err(invalid("section checksum mismatch"))
    }
}

/// Reads a whole segment from memory: header, blocks, dictionary, and every column. Returns
/// the dictionary and the row count. Used by the fuzzer (no panics on any input) and tests.
pub fn read_all(bytes: &[u8]) -> Option<(Dictionary, usize)> {
    let (_, blocks) = Segment::parse(bytes)?;
    let mut d = Dictionary::default();
    let mut rows = 0;
    for (off, h) in &blocks {
        let start = usize::try_from(*off).ok()? + BLOCK_HEADER;
        let body = bytes.get(start..start.checked_add(h.body_len as usize)?)?;
        let names = verified(h, 0, body.get(h.section_range(0))?).ok()?;
        let clients = verified(h, 1, body.get(h.section_range(1))?).ok()?;
        add_dictionary(&mut d, h, names, clients).ok()?;
        let mut cols = Columns::new(h.rows as usize);
        for col in COLUMNS {
            let k = col.section();
            let frame = verified(h, k, body.get(h.section_range(k))?).ok()?;
            cols.decode(col, frame).ok()?;
        }
        // IDs must point into the dictionary as it stands after this block.
        for r in 0..cols.rows {
            let (n, c) = (cols.get(Col::NameId, r), cols.get(Col::ClientId, r));
            if n >= d.name_count() as u64 || c >= d.clients.len() as u64 {
                return None;
            }
        }
        rows += cols.rows;
    }
    Some((d, rows))
}

/// Adds a block's dictionary delta to `d`.
pub fn add_dictionary(
    d: &mut Dictionary,
    h: &BlockHeader,
    names: &[u8],
    clients: &[u8],
) -> io::Result<()> {
    d.add_names(names, h.new_names)?;
    let raw = format::inflate(clients, MAX_SECTION).ok_or_else(|| invalid("client dictionary"))?;
    let mut r = Reader::new(&raw);
    for _ in 0..h.new_clients {
        let c = r.take(16).ok_or_else(|| invalid("client bytes"))?;
        let mut ip = [0u8; 16];
        ip.copy_from_slice(c);
        d.clients.push(ip);
    }
    Ok(())
}

type Footer = (Vec<(u64, BlockHeader)>, NameFilter);

fn read_footer<R: Read + Seek>(f: &mut R, len: u64) -> io::Result<Option<Footer>> {
    if len < (HEADER_LEN + TRAILER) as u64 {
        return Ok(None);
    }
    let mut tail = [0u8; TRAILER];
    f.seek(SeekFrom::Start(len - TRAILER as u64))?;
    f.read_exact(&mut tail)?;
    let Some((index_off, count, filter_len)) = format::read_trailer(&tail) else {
        return Ok(None);
    };
    let count = count as usize;
    let index_len = count
        .checked_mul(INDEX_ENTRY)
        .ok_or_else(|| invalid("index size"))?;
    let total = index_len as u64 + u64::from(filter_len) + TRAILER as u64;
    if index_off < HEADER_LEN as u64 || index_off.checked_add(total) != Some(len) {
        return Ok(None); // not a trailer we wrote: fall back to walking
    }
    let mut buf = vec![0u8; index_len + filter_len as usize];
    f.seek(SeekFrom::Start(index_off))?;
    f.read_exact(&mut buf)?;
    let Some(names) = NameFilter::read(&buf[index_len..]) else {
        return Ok(None);
    };
    let mut out = Vec::with_capacity(count);
    for e in buf[..index_len].as_chunks::<INDEX_ENTRY>().0 {
        let off = u64::from_le_bytes(e[..8].try_into().map_err(|_| invalid("index"))?);
        let Some(h) = BlockHeader::read(&e[8..]) else {
            return Ok(None);
        };
        if off + (BLOCK_HEADER as u64) + u64::from(h.body_len) > index_off {
            return Ok(None);
        }
        out.push((off, h));
    }
    Ok(Some((out, names)))
}

/// Walks block headers from the start; stops at the first one that doesn't fit or parse
/// (a segment still being written, or cut short by a crash).
fn walk_blocks<R: Read + Seek>(f: &mut R, len: u64) -> io::Result<Vec<(u64, BlockHeader)>> {
    let mut out = Vec::new();
    let mut off = HEADER_LEN as u64;
    let mut hb = vec![0u8; BLOCK_HEADER];
    while off + BLOCK_HEADER as u64 <= len {
        f.seek(SeekFrom::Start(off))?;
        f.read_exact(&mut hb)?;
        let Some(h) = BlockHeader::read(&hb) else {
            break;
        };
        let end = off + BLOCK_HEADER as u64 + u64::from(h.body_len);
        if end > len || h.body_len as usize > MAX_BODY {
            break;
        }
        out.push((off, h));
        off = end;
    }
    Ok(out)
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_owned())
}
