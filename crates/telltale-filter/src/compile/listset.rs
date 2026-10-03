//! `ListSetTable` (`spec/05` §3.1): interned, deduplicated list-ID bitsets. Each FST value
//! indexes one entry. An entry holds four bitsets, one per precedence class (§1 tiers), so a
//! single lookup answers "which enabled lists block / allow / important-block /
//! important-allow this name".
//!
//! Binary format (`listsets.bin`, little-endian):
//! `b"TTLS"`, `u32` format (1), `u32` words per bitset, `u32` entry count, then per entry four
//! bitsets of `words` × `u64`, in [`Class`] order.

use std::collections::HashMap;
use std::io::{self, Write};

/// Precedence classes, in `spec/05` §1 order (tier 1 first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    ImportantAllow = 0,
    ImportantBlock = 1,
    Allow = 2,
    Block = 3,
}

impl Class {
    pub const ALL: [Self; 4] = [
        Self::ImportantAllow,
        Self::ImportantBlock,
        Self::Allow,
        Self::Block,
    ];

    pub fn new(allow: bool, important: bool) -> Self {
        match (allow, important) {
            (true, true) => Self::ImportantAllow,
            (false, true) => Self::ImportantBlock,
            (true, false) => Self::Allow,
            (false, false) => Self::Block,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.get(usize::from(v)).copied()
    }
}

const MAGIC: &[u8; 4] = b"TTLS";
const FORMAT: u32 = 1;

/// Builds the table while merging; interning keeps it small (most domains share a few list
/// combinations).
#[derive(Debug)]
pub(crate) struct ListSetBuilder {
    words: usize,
    entries: Vec<u64>,
    index: HashMap<Box<[u64]>, u32>,
    scratch: Vec<u64>,
    /// The previous interned entry: sorted input repeats the same list set for long runs, so
    /// a slice compare usually replaces a hash lookup.
    last: Vec<u64>,
    last_id: Option<u32>,
}

impl ListSetBuilder {
    /// `lists` = number of list IDs (bitset width rounds up to whole `u64` words).
    pub(crate) fn new(lists: usize) -> Self {
        let words = lists.div_ceil(64).max(1);
        Self {
            words,
            entries: Vec::new(),
            index: HashMap::new(),
            scratch: vec![0; words * 4],
            last: vec![0; words * 4],
            last_id: None,
        }
    }

    /// Starts a new entry.
    pub(crate) fn clear(&mut self) {
        self.scratch.fill(0);
    }

    pub(crate) fn set(&mut self, class: Class, list: u16) {
        let bit = usize::from(list);
        self.scratch[class as usize * self.words + bit / 64] |= 1 << (bit % 64);
    }

    /// Lists set in any class of the current entry.
    pub(crate) fn union_count(&self) -> (u32, Option<u16>) {
        let mut count = 0;
        let mut first = None;
        for w in 0..self.words {
            let mut bits = 0;
            for c in 0..4 {
                bits |= self.scratch[c * self.words + w];
            }
            count += bits.count_ones();
            if first.is_none() && bits != 0 {
                let bit = w * 64 + bits.trailing_zeros() as usize;
                first = u16::try_from(bit).ok();
            }
        }
        (count, first)
    }

    /// Lists in the current entry, any class (for per-list entry counts).
    pub(crate) fn for_each_list(&self, mut f: impl FnMut(u16)) {
        for w in 0..self.words {
            let mut bits = 0;
            for c in 0..4 {
                bits |= self.scratch[c * self.words + w];
            }
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                if let Ok(id) = u16::try_from(w * 64 + b) {
                    f(id);
                }
            }
        }
    }

    /// Interns the current entry and returns its index.
    pub(crate) fn intern(&mut self) -> u32 {
        if let Some(id) = self.last_id
            && self.last == self.scratch
        {
            return id;
        }
        let id = if let Some(&id) = self.index.get(self.scratch.as_slice()) {
            id
        } else {
            let id = u32::try_from(self.index.len()).unwrap_or(u32::MAX);
            self.entries.extend_from_slice(&self.scratch);
            self.index
                .insert(self.scratch.clone().into_boxed_slice(), id);
            id
        };
        self.last.copy_from_slice(&self.scratch);
        self.last_id = Some(id);
        id
    }

    pub(crate) fn len(&self) -> usize {
        self.index.len()
    }

    pub(crate) fn finish(self) -> ListSetTable {
        ListSetTable {
            words: self.words,
            entries: self.entries,
        }
    }
}

/// The finished table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSetTable {
    words: usize,
    entries: Vec<u64>,
}

impl ListSetTable {
    pub fn len(&self) -> usize {
        self.entries.len() / (self.words * 4)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn words(&self) -> usize {
        self.words
    }

    /// The bitset of `class` in entry `id` (`words` × u64), or `None` for a bad index.
    pub fn get(&self, id: u32, class: Class) -> Option<&[u64]> {
        let start = (usize::try_from(id).ok()? * 4 + class as usize) * self.words;
        self.entries.get(start..start + self.words)
    }

    /// True if entry `id` has `list` in `class`.
    pub fn contains(&self, id: u32, class: Class, list: u16) -> bool {
        let bit = usize::from(list);
        self.get(id, class)
            .and_then(|b| b.get(bit / 64))
            .is_some_and(|w| w & (1 << (bit % 64)) != 0)
    }

    pub fn write(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(MAGIC)?;
        out.write_all(&FORMAT.to_le_bytes())?;
        out.write_all(
            &u32::try_from(self.words)
                .map_err(io::Error::other)?
                .to_le_bytes(),
        )?;
        out.write_all(
            &u32::try_from(self.len())
                .map_err(io::Error::other)?
                .to_le_bytes(),
        )?;
        for w in &self.entries {
            out.write_all(&w.to_le_bytes())?;
        }
        Ok(())
    }

    pub fn read(data: &[u8]) -> io::Result<Self> {
        let bad =
            |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("listsets.bin: {m}"));
        let u32_at = |i: usize| -> io::Result<u32> {
            data.get(i..i + 4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or_else(|| bad("truncated header"))
        };
        if data.get(..4) != Some(MAGIC.as_slice()) {
            return Err(bad("bad magic"));
        }
        if u32_at(4)? != FORMAT {
            return Err(bad("unsupported format"));
        }
        let words = u32_at(8)? as usize;
        let count = u32_at(12)? as usize;
        let body = &data[16..];
        let expected = count
            .checked_mul(words)
            .and_then(|n| n.checked_mul(4 * 8))
            .ok_or_else(|| bad("size overflow"))?;
        if words == 0 || body.len() != expected {
            return Err(bad("length mismatch"));
        }
        let entries = body
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
            .collect();
        Ok(Self { words, entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flt_003_interning_and_round_trip() {
        let mut b = ListSetBuilder::new(70);
        b.clear();
        b.set(Class::Block, 0);
        b.set(Class::Block, 69);
        let a = b.intern();
        b.clear();
        b.set(Class::Allow, 3);
        let c = b.intern();
        b.clear();
        b.set(Class::Block, 69);
        b.set(Class::Block, 0);
        assert_eq!(b.intern(), a, "same combination → same entry");
        assert_eq!(b.union_count(), (2, Some(0)));
        assert_eq!(b.len(), 2);
        let t = b.finish();
        assert!(t.contains(a, Class::Block, 69));
        assert!(!t.contains(a, Class::Allow, 69));
        assert!(t.contains(c, Class::Allow, 3));
        assert!(!t.contains(c, Class::Allow, 300));
        let mut buf = Vec::new();
        t.write(&mut buf).unwrap();
        assert_eq!(ListSetTable::read(&buf).unwrap(), t);
        assert!(ListSetTable::read(&buf[..buf.len() - 1]).is_err());
        assert!(ListSetTable::read(b"nope").is_err());
    }
}
