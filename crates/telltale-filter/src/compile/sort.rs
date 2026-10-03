//! External sort for compile records (`spec/05` §3.4 step 3).
//!
//! Records are `(key, list, class)`. Keys live in one byte arena (no allocation per record);
//! when arena + index exceed the memory budget, the sorted batch is written to a run file.
//! [`merge`] k-way merges every in-memory batch and run into one sorted, deduplicated stream.

use std::cmp::Ordering;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

/// One sorted record.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Record {
    pub(crate) key: Vec<u8>,
    pub(crate) list: u16,
    pub(crate) class: u8,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Item {
    /// First 8 key bytes, big-endian and zero-padded: most comparisons end here. Keys never
    /// contain NUL after the scope byte, so the padding sorts like "end of key".
    prefix: u64,
    off: u32,
    len: u16,
    list: u16,
    class: u8,
}

/// Bytes an index entry costs besides its key bytes.
const ITEM_COST: usize = std::mem::size_of::<Item>();

/// Collects records within a memory budget, spilling sorted runs to `tmp_dir`.
#[derive(Debug)]
pub(crate) struct Sorter {
    arena: Vec<u8>,
    items: Vec<Item>,
    budget: usize,
    tmp_dir: PathBuf,
    tag: String,
    runs: Vec<PathBuf>,
}

impl Sorter {
    pub(crate) fn new(budget: usize, tmp_dir: &Path, tag: &str) -> Self {
        Self {
            arena: Vec::new(),
            items: Vec::new(),
            budget: budget.max(1 << 20),
            tmp_dir: tmp_dir.to_owned(),
            tag: tag.to_owned(),
            runs: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, key: &[u8], list: u16, class: u8) -> io::Result<()> {
        let len = u16::try_from(key.len()).map_err(io::Error::other)?;
        if self.arena.len() + key.len() > u32::MAX as usize
            || self.arena.len() + self.items.len() * ITEM_COST >= self.budget
        {
            self.spill()?;
        }
        let off = u32::try_from(self.arena.len()).map_err(io::Error::other)?;
        self.arena.extend_from_slice(key);
        let mut head = [0u8; 8];
        let n = key.len().min(8);
        head[..n].copy_from_slice(&key[..n]);
        self.items.push(Item {
            prefix: u64::from_be_bytes(head),
            off,
            len,
            list,
            class,
        });
        Ok(())
    }

    fn sort(&mut self) {
        let arena = &self.arena;
        let key = |i: &Item| &arena[i.off as usize..i.off as usize + usize::from(i.len)];
        self.items.sort_unstable_by(|a, b| {
            a.prefix
                .cmp(&b.prefix)
                .then_with(|| key(a).cmp(key(b)))
                .then(a.list.cmp(&b.list))
                .then(a.class.cmp(&b.class))
        });
    }

    fn spill(&mut self) -> io::Result<()> {
        if self.items.is_empty() {
            return Ok(());
        }
        self.sort();
        let path = self
            .tmp_dir
            .join(format!("{}-run{}.bin", self.tag, self.runs.len()));
        let mut w = BufWriter::with_capacity(1 << 16, File::create(&path)?);
        let mut prev: Option<Item> = None;
        for it in &self.items {
            let key = &self.arena[it.off as usize..it.off as usize + usize::from(it.len)];
            if let Some(p) = prev
                && p.list == it.list
                && p.class == it.class
                && self.arena[p.off as usize..p.off as usize + usize::from(p.len)] == *key
            {
                continue;
            }
            w.write_all(&it.len.to_le_bytes())?;
            w.write_all(key)?;
            w.write_all(&it.list.to_le_bytes())?;
            w.write_all(&[it.class])?;
            prev = Some(*it);
        }
        w.flush()?;
        self.runs.push(path);
        self.arena.clear();
        self.items.clear();
        Ok(())
    }

    /// Number of run files written so far.
    pub(crate) fn runs(&self) -> usize {
        self.runs.len()
    }

    /// Finishes collection: the remaining batch stays in memory (sorted) unless runs exist
    /// already, in which case it is spilled too so the merge has uniform sources.
    pub(crate) fn finish(mut self) -> io::Result<Vec<Source>> {
        let mut sources = Vec::new();
        if self.runs.is_empty() {
            self.sort();
            sources.push(Source::Memory {
                arena: std::mem::take(&mut self.arena),
                items: std::mem::take(&mut self.items),
                next: 0,
            });
        } else {
            self.spill()?;
            for path in &self.runs {
                sources.push(Source::File {
                    reader: BufReader::with_capacity(1 << 16, File::open(path)?),
                    path: path.clone(),
                });
            }
        }
        Ok(sources)
    }
}

/// A sorted input to the merge.
#[derive(Debug)]
pub(crate) enum Source {
    Memory {
        arena: Vec<u8>,
        items: Vec<Item>,
        next: usize,
    },
    File {
        reader: BufReader<File>,
        path: PathBuf,
    },
}

impl Source {
    /// Reads the next record into `rec`, reusing its key buffer. Returns false at the end.
    fn next_into(&mut self, rec: &mut Record) -> io::Result<bool> {
        match self {
            Self::Memory { arena, items, next } => {
                let Some(it) = items.get(*next) else {
                    return Ok(false);
                };
                *next += 1;
                rec.key.clear();
                rec.key.extend_from_slice(
                    &arena[it.off as usize..it.off as usize + usize::from(it.len)],
                );
                rec.list = it.list;
                rec.class = it.class;
                Ok(true)
            }
            Self::File { reader, .. } => {
                let mut len = [0u8; 2];
                match reader.read_exact(&mut len) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
                    Err(e) => return Err(e),
                }
                rec.key.resize(usize::from(u16::from_le_bytes(len)), 0);
                reader.read_exact(&mut rec.key)?;
                let mut tail = [0u8; 3];
                reader.read_exact(&mut tail)?;
                rec.list = u16::from_le_bytes([tail[0], tail[1]]);
                rec.class = tail[2];
                Ok(true)
            }
        }
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        if let Self::File { path, .. } = self {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn cmp(a: &Record, b: &Record) -> Ordering {
    a.key
        .cmp(&b.key)
        .then(a.list.cmp(&b.list))
        .then(a.class.cmp(&b.class))
}

/// Calls `f` for every distinct record across `sources`, in sorted order.
///
/// Sources are few (one per parser thread, plus spilled runs), so the next record is found
/// by a linear scan of each source's current record; buffers are reused, so the merge does
/// no allocation per record.
pub(crate) fn merge(
    mut sources: Vec<Source>,
    mut f: impl FnMut(&Record) -> io::Result<()>,
) -> io::Result<()> {
    let mut heads: Vec<Option<Record>> = Vec::with_capacity(sources.len());
    for s in &mut sources {
        let mut r = Record::default();
        heads.push(s.next_into(&mut r)?.then_some(r));
    }
    let mut last = Record::default();
    let mut have_last = false;
    loop {
        let mut min: Option<usize> = None;
        for (i, h) in heads.iter().enumerate() {
            if let Some(r) = h
                && min.is_none_or(|m| {
                    heads[m]
                        .as_ref()
                        .is_some_and(|mr| cmp(r, mr) == Ordering::Less)
                })
            {
                min = Some(i);
            }
        }
        let Some(i) = min else {
            return Ok(());
        };
        if let Some(rec) = heads[i].as_mut() {
            if !have_last || cmp(rec, &last) != Ordering::Equal {
                f(rec)?;
                last.key.clone_from(&rec.key);
                last.list = rec.list;
                last.class = rec.class;
                have_last = true;
            }
            if !sources[i].next_into(rec)? {
                heads[i] = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(sources: Vec<Source>) -> Vec<(String, u16, u8)> {
        let mut out = Vec::new();
        merge(sources, |r| {
            out.push((String::from_utf8(r.key.clone()).unwrap(), r.list, r.class));
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn flt_004_sort_in_memory_and_with_spills() {
        let tmp = tempfile::tempdir().unwrap();
        let input: Vec<(String, u16, u8)> = (0..5000u32)
            .map(|i| {
                (
                    format!("com.example.n{}.", (i * 7919) % 2500),
                    u16::try_from(i % 3).unwrap(),
                    3,
                )
            })
            .collect();
        let mut expected = input.clone();
        expected.sort();
        expected.dedup();

        // Large budget: one in-memory source.
        let mut s = Sorter::new(64 << 20, tmp.path(), "mem");
        for (k, l, c) in &input {
            s.push(k.as_bytes(), *l, *c).unwrap();
        }
        assert_eq!(s.runs(), 0);
        assert_eq!(collect(s.finish().unwrap()), expected);

        // Tiny budget (clamped to 1 MiB) with many records: spills, then merges.
        let mut s = Sorter::new(0, tmp.path(), "spill");
        for round in 0..30 {
            for (k, l, c) in &input {
                s.push(format!("{k}{round}").as_bytes(), *l, *c).unwrap();
            }
        }
        assert!(s.runs() > 1, "expected spills, got {}", s.runs());
        let merged = collect(s.finish().unwrap());
        assert_eq!(merged.len(), expected.len() * 30);
        assert!(
            merged.windows(2).all(|w| w[0] < w[1]),
            "sorted and distinct"
        );
        // Run files are removed once merged.
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }
}
