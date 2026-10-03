//! Writes the sharded domain FSTs (`<scope>-<shard>.fst`), optionally on worker threads.
//!
//! The merge produces keys in global sorted order; every shard receives a subsequence of that
//! order, which is still sorted, so each shard's FST can be built independently. There is one
//! shard per compile thread: with one thread everything is built inline (one FST per scope);
//! with more, worker `i` builds shard `i` of every scope from batches, so FST construction
//! (the most expensive compile step) runs in parallel with the merge and with itself.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::JoinHandle;

use fst::MapBuilder;

use super::CompileError;
use crate::snapshot::{SCOPE_NAMES, domain_fst, shard_of};

type FstWriter = MapBuilder<BufWriter<File>>;

/// Keys per batch sent to a worker.
const BATCH: usize = 8192;

#[derive(Default)]
struct Batch {
    keys: Vec<u8>,
    /// (FST index, key start, key end, value)
    items: Vec<(u16, u32, u32, u32)>,
}

pub(crate) struct Worker {
    tx: SyncSender<Batch>,
    batch: Batch,
    handle: JoinHandle<Result<(), CompileError>>,
}

/// All `3 × shards` domain FSTs.
pub(crate) struct FstSink {
    shards: usize,
    mode: Mode,
}

enum Mode {
    Direct(Vec<FstWriter>),
    Threaded(Vec<Worker>),
}

impl FstSink {
    /// Creates every FST file in `dir`, with `shards` shards per scope (one per worker when
    /// `shards > 1`).
    pub(crate) fn new(dir: &Path, shards: usize) -> Result<Self, CompileError> {
        let shards = shards.max(1);
        let mut writers = Vec::with_capacity(SCOPE_NAMES.len() * shards);
        for scope in 0..SCOPE_NAMES.len() {
            for shard in 0..shards {
                let file = File::create(dir.join(domain_fst(scope, shard)))?;
                writers.push(MapBuilder::new(BufWriter::new(file))?);
            }
        }
        if shards == 1 {
            return Ok(Self {
                shards,
                mode: Mode::Direct(writers),
            });
        }
        let total = writers.len();
        let mut owned: Vec<Vec<(usize, FstWriter)>> = (0..shards).map(|_| Vec::new()).collect();
        for (i, w) in writers.into_iter().enumerate() {
            owned[i % shards].push((i, w));
        }
        let mut workers = Vec::with_capacity(shards);
        for (t, mine) in owned.into_iter().enumerate() {
            let (tx, rx) = sync_channel::<Batch>(4);
            let handle = std::thread::Builder::new()
                .name(format!("telltale-fst-{t}"))
                .spawn(move || -> Result<(), CompileError> {
                    super::lower_priority();
                    let mut slots: Vec<Option<FstWriter>> = (0..total).map(|_| None).collect();
                    for (i, w) in mine {
                        slots[i] = Some(w);
                    }
                    for batch in rx {
                        for &(idx, s, e, v) in &batch.items {
                            if let Some(w) = slots[usize::from(idx)].as_mut() {
                                w.insert(&batch.keys[s as usize..e as usize], u64::from(v))?;
                            }
                        }
                    }
                    for w in slots.into_iter().flatten() {
                        w.into_inner()?.flush()?;
                    }
                    Ok(())
                })?;
            workers.push(Worker {
                tx,
                batch: Batch::default(),
                handle,
            });
        }
        Ok(Self {
            shards,
            mode: Mode::Threaded(workers),
        })
    }

    /// Adds `key` (scope byte stripped) with list-set `value` to its shard.
    pub(crate) fn insert(
        &mut self,
        scope: usize,
        key: &[u8],
        value: u32,
    ) -> Result<(), CompileError> {
        let shard = shard_of(key, self.shards);
        let idx = scope * self.shards + shard;
        match &mut self.mode {
            Mode::Direct(writers) => writers[idx].insert(key, u64::from(value))?,
            Mode::Threaded(workers) => {
                let w = &mut workers[shard];
                let start = u32::try_from(w.batch.keys.len()).map_err(io::Error::other)?;
                w.batch.keys.extend_from_slice(key);
                let end = u32::try_from(w.batch.keys.len()).map_err(io::Error::other)?;
                let idx = u16::try_from(idx).map_err(io::Error::other)?;
                w.batch.items.push((idx, start, end, value));
                if w.batch.items.len() >= BATCH {
                    let batch = std::mem::take(&mut w.batch);
                    if w.tx.send(batch).is_err() {
                        // The worker stopped early; its error surfaces in `finish`.
                        return Err(io::Error::other("FST worker exited").into());
                    }
                }
            }
        }
        Ok(())
    }

    /// Flushes every FST to disk.
    pub(crate) fn finish(self) -> Result<(), CompileError> {
        match self.mode {
            Mode::Direct(writers) => {
                for w in writers {
                    w.into_inner()?.flush()?;
                }
                Ok(())
            }
            Mode::Threaded(workers) => {
                let mut first_err = None;
                for w in workers {
                    let Worker { tx, batch, handle } = w;
                    if !batch.items.is_empty() {
                        let _ = tx.send(batch);
                    }
                    drop(tx);
                    let r = handle
                        .join()
                        .unwrap_or_else(|_| Err(io::Error::other("FST worker panicked").into()));
                    if let Err(e) = r {
                        first_err.get_or_insert(e);
                    }
                }
                first_err.map_or(Ok(()), Err)
            }
        }
    }
}
