//! Space-Saving top-K (Metwally et al., 2005) over an indexed min-heap: O(log K) per item,
//! fixed memory, and each count overestimates by at most its recorded `error`.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Clone)]
struct Entry<K> {
    key: K,
    count: u64,
    error: u64,
}

/// The `capacity` heaviest keys seen.
#[derive(Debug, Clone)]
pub struct SpaceSaving<K> {
    capacity: usize,
    /// Key → position in `heap`.
    pos: HashMap<K, usize>,
    /// Min-heap by count: the root is the next to be replaced.
    heap: Vec<Entry<K>>,
}

/// One reported key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Top<K> {
    pub key: K,
    /// Upper bound of the true count.
    pub count: u64,
    /// The true count is at least `count - error`.
    pub error: u64,
}

impl<K: Hash + Eq + Clone> SpaceSaving<K> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            pos: HashMap::new(),
            heap: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Counts one occurrence of `key`; `own` makes the stored key, and runs (allocating, for
    /// boxed keys) only when a new key is stored.
    pub fn offer<Q>(&mut self, key: &Q, own: impl FnOnce(&Q) -> K)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if let Some(&i) = self.pos.get(key) {
            self.heap[i].count += 1;
            self.sift_down(i);
            return;
        }
        let owned = own(key);
        if self.heap.len() < self.capacity {
            self.heap.push(Entry {
                key: owned.clone(),
                count: 1,
                error: 0,
            });
            let i = self.heap.len() - 1;
            self.pos.insert(owned, i);
            self.sift_up(i);
            return;
        }
        // Replace the minimum: the newcomer inherits its count as possible overestimate.
        let min = self.heap[0].count;
        let old = std::mem::replace(
            &mut self.heap[0],
            Entry {
                key: owned.clone(),
                count: min + 1,
                error: min,
            },
        );
        self.pos.remove::<K>(&old.key);
        self.pos.insert(owned, 0);
        self.sift_down(0);
    }

    /// The `n` heaviest keys, heaviest first.
    pub fn top(&self, n: usize) -> Vec<Top<K>> {
        let mut v: Vec<Top<K>> = self
            .heap
            .iter()
            .map(|e| Top {
                key: e.key.clone(),
                count: e.count,
                error: e.error,
            })
            .collect();
        v.sort_by(|a, b| b.count.cmp(&a.count).then(a.error.cmp(&b.error)));
        v.truncate(n);
        v
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        for i in [a, b] {
            if let Some(p) = self.pos.get_mut(&self.heap[i].key) {
                *p = i;
            }
        }
    }

    fn sift_up(&mut self, mut i: usize) {
        while i > 0 {
            let parent = (i - 1) / 2;
            if self.heap[i].count >= self.heap[parent].count {
                break;
            }
            self.swap(i, parent);
            i = parent;
        }
    }

    fn sift_down(&mut self, mut i: usize) {
        loop {
            let (l, r) = (2 * i + 1, 2 * i + 2);
            let mut smallest = i;
            if l < self.heap.len() && self.heap[l].count < self.heap[smallest].count {
                smallest = l;
            }
            if r < self.heap.len() && self.heap[r].count < self.heap[smallest].count {
                smallest = r;
            }
            if smallest == i {
                return;
            }
            self.swap(i, smallest);
            i = smallest;
        }
    }
}
