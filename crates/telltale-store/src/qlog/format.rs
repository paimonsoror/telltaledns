//! Segment file format (`spec/06` §4, ADR-027). Little-endian throughout.
//!
//! ```text
//! segment  = header(32) block* [footer]
//! header   = "VQLG" version:u16 node:u16 hour:u64 part:u32 reserved[12]
//! block    = block_header(BLOCK_HEADER) body(body_len)
//! body     = frame*   ; one zstd frame per section, back to back:
//!                     ; name dictionary delta, client dictionary delta, then COLUMNS
//! footer   = (offset:u64 block_header)* name_filter
//!            index_offset:u64 count:u32 filter_len:u32 "VQFT"
//! ```
//!
//! A block header carries everything search needs to prune (time range, status/RCODE masks,
//! max latency, a bloom over name and client keys) and a table of every section's length and
//! xxh3 checksum, so a search reads and verifies only the sections it needs: one column
//! of a block is one positional read. A segment without a footer (still being written, or
//! cut short by a crash) is read by walking block headers; the footer is only a faster path
//! to the same headers.

/// Segment magic and version.
pub const SEGMENT_MAGIC: &[u8; 4] = b"VQLG";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 32;
const BLOCK_MAGIC: &[u8; 4] = b"VQBK";
const FOOTER_MAGIC: &[u8; 4] = b"VQFT";
/// Bloom filter bits per block (1 KiB).
pub const BLOOM_BITS: usize = 8192;
const BLOOM_BYTES: usize = BLOOM_BITS / 8;
/// Rows per block at most (`spec/06` §4).
pub const MAX_ROWS: usize = 8192;
/// Largest body a reader accepts (guards against corrupt lengths before allocating).
pub const MAX_BODY: usize = 64 << 20;

/// The columns, in body order after the two dictionary sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Col {
    /// `ts_us - min_ts`, varint.
    Ts,
    NameId,
    ClientId,
    ClientRef,
    Group,
    Qtype,
    Qclass,
    /// u8; 0xFF = no response.
    Rcode,
    /// u8.
    Status,
    /// u8.
    Proto,
    Flags,
    /// `list + 1`, 0 = no rule.
    RuleList,
    /// u8: kind | allow << 7.
    RuleKind,
    Upstream,
    /// u8.
    Attempts,
    TotalUs,
    UpstreamUs,
    RespSize,
    Answers,
}

pub const COLUMNS: [Col; 19] = [
    Col::Ts,
    Col::NameId,
    Col::ClientId,
    Col::ClientRef,
    Col::Group,
    Col::Qtype,
    Col::Qclass,
    Col::Rcode,
    Col::Status,
    Col::Proto,
    Col::Flags,
    Col::RuleList,
    Col::RuleKind,
    Col::Upstream,
    Col::Attempts,
    Col::TotalUs,
    Col::UpstreamUs,
    Col::RespSize,
    Col::Answers,
];

impl Col {
    /// One byte per row (no varint).
    pub const fn is_byte(self) -> bool {
        matches!(
            self,
            Self::Rcode | Self::Status | Self::Proto | Self::RuleKind | Self::Attempts
        )
    }

    /// Section index in the body.
    pub const fn section(self) -> usize {
        DICT_SECTIONS + self as usize
    }
}

/// Sections before the columns (name and client dictionary deltas).
pub const DICT_SECTIONS: usize = 2;
pub const SECTIONS: usize = DICT_SECTIONS + COLUMNS.len();

/// Fixed block header size.
pub const BLOCK_HEADER: usize =
    4 + 4 + 4 + 4 + 4 + 8 + 8 + 4 + 4 + 4 + SECTIONS * (4 + 8) + BLOOM_BYTES;
/// Offset of the section table inside a block header.
pub const SECTION_TABLE_AT: usize = 4 + 4 + 4 + 4 + 4 + 8 + 8 + 4 + 4 + 4;

/// What a block header says about its rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub body_len: u32,
    pub rows: u32,
    /// Dictionary entries this block adds (names, clients).
    pub new_names: u32,
    pub new_clients: u32,
    pub min_ts: u64,
    pub max_ts: u64,
    /// Bit `s` set if some row has status `s`.
    pub status_mask: u32,
    /// Bit `r` for RCODE `r` (0–15), bit 16 for "other", bit 17 for no response.
    pub rcode_mask: u32,
    pub max_total_us: u32,
    /// Per section: compressed length and xxh3 checksum of the frame.
    pub sections: [(u32, [u8; 8]); SECTIONS],
    pub bloom: Box<[u8; BLOOM_BYTES]>,
}

impl BlockHeader {
    pub fn empty() -> Self {
        Self {
            body_len: 0,
            rows: 0,
            new_names: 0,
            new_clients: 0,
            min_ts: u64::MAX,
            max_ts: 0,
            status_mask: 0,
            rcode_mask: 0,
            max_total_us: 0,
            sections: [(0, [0; 8]); SECTIONS],
            bloom: Box::new([0; BLOOM_BYTES]),
        }
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(BLOCK_MAGIC);
        out.extend_from_slice(&self.body_len.to_le_bytes());
        out.extend_from_slice(&self.rows.to_le_bytes());
        out.extend_from_slice(&self.new_names.to_le_bytes());
        out.extend_from_slice(&self.new_clients.to_le_bytes());
        out.extend_from_slice(&self.min_ts.to_le_bytes());
        out.extend_from_slice(&self.max_ts.to_le_bytes());
        out.extend_from_slice(&self.status_mask.to_le_bytes());
        out.extend_from_slice(&self.rcode_mask.to_le_bytes());
        out.extend_from_slice(&self.max_total_us.to_le_bytes());
        for (len, sum) in &self.sections {
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(sum);
        }
        out.extend_from_slice(&self.bloom[..]);
    }

    pub fn read(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.take(4)? != BLOCK_MAGIC {
            return None;
        }
        let mut h = Self {
            body_len: r.u32()?,
            rows: r.u32()?,
            new_names: r.u32()?,
            new_clients: r.u32()?,
            min_ts: r.u64()?,
            max_ts: r.u64()?,
            status_mask: r.u32()?,
            rcode_mask: r.u32()?,
            max_total_us: r.u32()?,
            ..Self::empty()
        };
        for s in &mut h.sections {
            *s = (r.u32()?, r.take(8)?.try_into().ok()?);
        }
        h.bloom = Box::new(r.take(BLOOM_BYTES)?.try_into().ok()?);
        let total: u64 = h.sections.iter().map(|(l, _)| u64::from(*l)).sum();
        let sane = usize::try_from(h.body_len).is_ok_and(|n| n <= MAX_BODY)
            && total == u64::from(h.body_len)
            && usize::try_from(h.rows).is_ok_and(|n| n <= MAX_ROWS)
            && h.new_names <= h.rows
            && h.new_clients <= h.rows;
        sane.then_some(h)
    }

    /// Byte range of section `k` within the body.
    pub fn section_range(&self, k: usize) -> std::ops::Range<usize> {
        let start: usize = self.sections[..k].iter().map(|(l, _)| *l as usize).sum();
        start..start + self.sections[k].0 as usize
    }

    /// Sets the bloom bits for a key: [`name_key`] or [`client_key`]. Keys are content
    /// hashes, not dictionary IDs, so a search can rule a block out before reading any
    /// dictionary.
    pub fn bloom_insert(&mut self, key: u64) {
        for bit in bloom_bits(key) {
            self.bloom[bit / 8] |= 1 << (bit % 8);
        }
    }

    pub fn bloom_may_contain(&self, key: u64) -> bool {
        bloom_bits(key)
            .iter()
            .all(|&bit| self.bloom[bit / 8] & (1 << (bit % 8)) != 0)
    }
}

/// Bloom key of a (lowercase, wire-format) name.
pub fn name_key(wire: &[u8]) -> u64 {
    xxhash_rust::xxh3::xxh3_64_with_seed(wire, 0x6E61_6D65)
}

/// Bloom key of a client address.
pub fn client_key(ip: &[u8; 16]) -> u64 {
    xxhash_rust::xxh3::xxh3_64_with_seed(ip, 0x6970_6970)
}

/// Three bit positions from a key (re-mixed, so name and client keys spread alike).
fn bloom_bits(key: u64) -> [usize; 3] {
    let mut z = key;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    let m = BLOOM_BITS as u64 - 1;
    #[allow(clippy::cast_possible_truncation)] // masked to 13 bits
    [
        (z & m) as usize,
        ((z >> 21) & m) as usize,
        ((z >> 42) & m) as usize,
    ]
}

/// Segment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    pub node: u16,
    /// Hours since the Unix epoch.
    pub hour: u64,
    pub part: u32,
}

impl SegmentHeader {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(SEGMENT_MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.node.to_le_bytes());
        out.extend_from_slice(&self.hour.to_le_bytes());
        out.extend_from_slice(&self.part.to_le_bytes());
        out.extend_from_slice(&[0; 12]);
    }

    pub fn read(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.take(4)? != SEGMENT_MAGIC || r.u16()? != VERSION {
            return None;
        }
        Some(Self {
            node: r.u16()?,
            hour: r.u64()?,
            part: r.u32()?,
        })
    }
}

/// Footer: the block headers with their offsets (one sequential read), then the segment's
/// name filter, then the trailer.
pub fn write_footer(
    index: &[(u64, BlockHeader)],
    names: &NameFilter,
    out: &mut Vec<u8>,
    index_offset: u64,
) {
    for (off, h) in index {
        out.extend_from_slice(&off.to_le_bytes());
        h.write(out);
    }
    let before = out.len();
    names.write(out);
    let filter_len = out.len() - before;
    out.extend_from_slice(&index_offset.to_le_bytes());
    out.extend_from_slice(&u32::try_from(index.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(&u32::try_from(filter_len).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(FOOTER_MAGIC);
}

/// Trailer length.
pub const TRAILER: usize = 20;

/// The trailer at the end of a finished segment: (index offset, block count, filter length).
pub fn read_trailer(tail: &[u8]) -> Option<(u64, u32, u32)> {
    let t = tail.get(tail.len().checked_sub(TRAILER)?..)?;
    let mut r = Reader::new(t);
    let off = r.u64()?;
    let count = r.u32()?;
    let filter = r.u32()?;
    (r.take(4)? == FOOTER_MAGIC).then_some((off, count, filter))
}

/// Every name in a finished segment, as a bloom filter (~10 bits and 7 probes per name,
/// ~0.8% false positives). The block blooms are 1 KiB each, which is too small to rule out
/// a name in blocks holding thousands of distinct names; this one lets an exact-name search
/// skip a whole segment after one small read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameFilter {
    words: Vec<u64>,
}

/// Largest filter a reader accepts (8 Mi bits; a segment part has at most 64 Ki names).
const MAX_FILTER_WORDS: usize = 1 << 17;
const FILTER_PROBES: u64 = 7;

impl NameFilter {
    pub fn build(keys: &[u64]) -> Self {
        let bits = (keys.len() * 10).next_power_of_two().max(1024);
        let mut f = Self {
            words: vec![0; bits / 64],
        };
        for &k in keys {
            for bit in f.probes(k) {
                f.words[bit / 64] |= 1 << (bit % 64);
            }
        }
        f
    }

    fn probes(&self, key: u64) -> impl Iterator<Item = usize> + use<> {
        let mask = (self.words.len() * 64 - 1) as u64;
        let h2 = key.rotate_left(32) | 1;
        #[allow(clippy::cast_possible_truncation)] // masked below the filter size
        (0..FILTER_PROBES).map(move |i| (key.wrapping_add(i.wrapping_mul(h2)) & mask) as usize)
    }

    pub fn may_contain(&self, key: u64) -> bool {
        self.probes(key)
            .all(|bit| self.words[bit / 64] & (1 << (bit % 64)) != 0)
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        for w in &self.words {
            out.extend_from_slice(&w.to_le_bytes());
        }
    }

    pub fn read(b: &[u8]) -> Option<Self> {
        let n = b.len() / 8;
        if !b.len().is_multiple_of(8)
            || !n.is_power_of_two()
            || !(16..=MAX_FILTER_WORDS).contains(&n)
        {
            return None;
        }
        Some(Self {
            words: b
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| u64::from_le_bytes(*c))
                .collect(),
        })
    }
}

/// Size of one footer index entry.
pub const INDEX_ENTRY: usize = 8 + BLOCK_HEADER;

/// Checksum of a section frame: xxh3-64. It only detects corruption (nothing here is
/// content-addressed), and BLAKE3 over every section was a measurable share of a 30-day
/// search on a Pi.
pub fn checksum(frame: &[u8]) -> [u8; 8] {
    xxhash_rust::xxh3::xxh3_64_with_seed(frame, 0x716C_6F67).to_le_bytes()
}

/// Recomputes every section checksum in a segment, in place (block headers only; a
/// footer, if any, keeps the old sums and is then ignored by readers as inconsistent). For
/// the fuzzer: lets mutations reach decoding instead of stopping at a checksum.
pub fn repair_checksums(seg: &mut [u8]) {
    let mut off = HEADER_LEN;
    while let Some(h) = seg.get(off..off + BLOCK_HEADER).and_then(BlockHeader::read) {
        let start = off + BLOCK_HEADER;
        let end = start + h.body_len as usize;
        if end > seg.len() {
            return;
        }
        for k in 0..SECTIONS {
            let r = h.section_range(k);
            let sum = checksum(&seg[start + r.start..start + r.end]);
            let at = off + SECTION_TABLE_AT + k * 12 + 4;
            seg[at..at + 8].copy_from_slice(&sum);
        }
        off = end;
    }
}

pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        #[allow(clippy::cast_possible_truncation)] // low 7 bits
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    #[allow(clippy::cast_possible_truncation)] // < 0x80
    out.push(v as u8);
}

/// Little-endian cursor over a byte slice; every read is bounds-checked.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let b = self.buf.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(b)
    }
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            v |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
}

/// Decompresses one section, refusing outputs over `limit` bytes.
pub fn inflate(frame: &[u8], limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    inflate_into(frame, limit, &mut out)?;
    Some(out)
}

/// Decompresses one section onto the end of `out` (one bulk call when the frame records its
/// size, as ours do), refusing more than `limit` new bytes. Returns the bytes added.
pub fn inflate_into(frame: &[u8], limit: usize, out: &mut Vec<u8>) -> Option<usize> {
    let start = out.len();
    if let Ok(Some(n)) = zstd::zstd_safe::get_frame_content_size(frame)
        && let Ok(n) = usize::try_from(n)
        && n <= limit
    {
        out.resize(start + n, 0);
        // One decompression context per thread: creating one per section cost more than
        // the decompression itself in a 30-day search.
        let got = DCTX.with(|d| {
            let mut d = d.try_borrow_mut().ok()?;
            let d = d.as_mut()?;
            d.decompress_to_buffer(frame, &mut out[start..]).ok()
        });
        if got == Some(n) {
            return Some(n);
        }
        out.truncate(start);
        return None;
    }
    let s = stream_inflate(frame, limit)?;
    out.extend_from_slice(&s);
    Some(s.len())
}

thread_local! {
    static DCTX: std::cell::RefCell<Option<zstd::bulk::Decompressor<'static>>> =
        std::cell::RefCell::new(zstd::bulk::Decompressor::new().ok());
}

/// Streaming fallback for frames without a recorded size.
fn stream_inflate(frame: &[u8], limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut d = zstd::stream::read::Decoder::new(frame).ok()?;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = std::io::Read::read(&mut d, &mut buf).ok()?;
        if n == 0 {
            return Some(out);
        }
        if out.len() + n > limit {
            return None;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// Compresses one section (level 3, `spec/06` §4).
pub fn deflate(raw: &[u8]) -> std::io::Result<Vec<u8>> {
    zstd::bulk::compress(raw, 3)
}
