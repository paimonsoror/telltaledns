//! S3-FIFO eviction (Yang et al., SOSP '23): a small probationary FIFO, a main FIFO with
//! lazy promotion (2-bit frequency), and a ghost FIFO of recently evicted key fingerprints.
//!
//! Lookups are O(1) and allocation-free: they only bump a counter. Queue entries carry a
//! generation number so removals are lazy (stale queue entries are skipped on eviction).

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hash};

/// Max frequency counter value (2 bits).
const MAX_FREQ: u8 = 3;
/// Share of capacity given to the small FIFO (the paper uses 10%).
const SMALL_PCT: usize = 10;

#[derive(Debug)]
struct Node<V> {
    value: V,
    weight: usize,
    freq: u8,
    in_main: bool,
    generation: u32,
}

/// One eviction step; returns whether anything was evicted or promoted.
type Evict<K, V, S> = fn(&mut S3Fifo<K, V, S>) -> bool;

/// A weighted S3-FIFO map. `K` should be cheap to copy (queues hold copies).
#[derive(Debug)]
pub struct S3Fifo<K, V, S> {
    map: HashMap<K, Node<V>, S>,
    small: VecDeque<(K, u32)>,
    main: VecDeque<(K, u32)>,
    ghost: VecDeque<u64>,
    ghost_set: HashSet<u64, S>,
    small_weight: usize,
    main_weight: usize,
    capacity: usize,
    max_entries: usize,
    next_gen: u32,
    evictions: u64,
}

impl<K, V, S> S3Fifo<K, V, S>
where
    K: Copy + Eq + Hash,
    S: BuildHasher + Clone,
{
    /// `capacity` is a total weight budget; `max_entries` caps the count (0 = unlimited).
    pub fn new(capacity: usize, max_entries: usize, hasher: S) -> Self {
        Self {
            map: HashMap::with_hasher(hasher.clone()),
            small: VecDeque::new(),
            main: VecDeque::new(),
            ghost: VecDeque::new(),
            ghost_set: HashSet::with_hasher(hasher),
            small_weight: 0,
            main_weight: 0,
            capacity: capacity.max(1),
            max_entries,
            next_gen: 0,
            evictions: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Total weight currently stored.
    pub fn weight(&self) -> usize {
        self.small_weight + self.main_weight
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Looks up `key` and records an access. Allocation-free.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let node = self.map.get_mut(key)?;
        node.freq = (node.freq + 1).min(MAX_FREQ);
        Some(&mut node.value)
    }

    /// Looks up `key` without recording an access.
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|n| &n.value)
    }

    /// Inserts or replaces `key`, then evicts until within budget.
    pub fn insert(&mut self, key: K, value: V, weight: usize) {
        if let Some(node) = self.map.get_mut(&key) {
            let old = node.weight;
            node.value = value;
            node.weight = weight;
            if node.in_main {
                self.main_weight = self.main_weight - old + weight;
            } else {
                self.small_weight = self.small_weight - old + weight;
            }
        } else {
            let fp = self.fingerprint(&key);
            let to_main = self.ghost_set.remove(&fp);
            let generation = self.next_gen;
            self.next_gen = self.next_gen.wrapping_add(1);
            self.map.insert(
                key,
                Node {
                    value,
                    weight,
                    freq: 0,
                    in_main: to_main,
                    generation,
                },
            );
            if to_main {
                self.main.push_back((key, generation));
                self.main_weight += weight;
            } else {
                self.small.push_back((key, generation));
                self.small_weight += weight;
            }
        }
        self.evict_to_fit();
    }

    /// Removes `key`, returning its value. Queue entries are cleaned up lazily.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let node = self.map.remove(key)?;
        if node.in_main {
            self.main_weight -= node.weight;
        } else {
            self.small_weight -= node.weight;
        }
        Some(node.value)
    }

    /// Visits every entry without recording an access (inspection, T6.13).
    pub fn for_each(&self, mut f: impl FnMut(&K, &V)) {
        for (k, n) in &self.map {
            f(k, &n.value);
        }
    }

    /// Removes every entry for which `pred` returns true.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        let (mut small, mut main) = (0, 0);
        self.map.retain(|k, n| {
            let k = keep(k, &n.value);
            if !k {
                if n.in_main {
                    main += n.weight;
                } else {
                    small += n.weight;
                }
            }
            k
        });
        self.small_weight -= small;
        self.main_weight -= main;
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.small.clear();
        self.main.clear();
        self.small_weight = 0;
        self.main_weight = 0;
    }

    fn fingerprint(&self, key: &K) -> u64 {
        self.map.hasher().hash_one(key)
    }

    fn over_budget(&self) -> bool {
        self.weight() > self.capacity || (self.max_entries > 0 && self.map.len() > self.max_entries)
    }

    fn evict_to_fit(&mut self) {
        while self.over_budget() {
            let small_target = self.capacity.saturating_mul(SMALL_PCT) / 100;
            // Order matters (it decides which queue loses an entry), so spell it out.
            let (first, second): (Evict<K, V, S>, Evict<K, V, S>) =
                if self.small_weight > small_target || self.main.is_empty() {
                    (Self::evict_small, Self::evict_main)
                } else {
                    (Self::evict_main, Self::evict_small)
                };
            let evicted = first(self) || second(self);
            if !evicted {
                break;
            }
        }
        // Compact queues that are mostly stale entries from lazy removals.
        if self.small.len() > 2 * self.map.len() + 64 || self.main.len() > 2 * self.map.len() + 64 {
            let map = &self.map;
            let live = |(k, g): &(K, u32)| map.get(k).is_some_and(|n| n.generation == *g);
            self.small.retain(live);
            self.main.retain(live);
        }
    }

    /// Pops the small FIFO: accessed entries move to main, others die (fingerprint → ghost).
    fn evict_small(&mut self) -> bool {
        while let Some((key, generation)) = self.small.pop_front() {
            let Some(node) = self.map.get_mut(&key) else {
                continue;
            };
            if node.generation != generation || node.in_main {
                continue;
            }
            if node.freq > 0 {
                node.in_main = true;
                node.freq = 0;
                self.small_weight -= node.weight;
                self.main_weight += node.weight;
                self.main.push_back((key, generation));
                // Promotion freed small space but not total; keep evicting.
                return true;
            }
            let fp = self.fingerprint(&key);
            self.remove(&key);
            self.evictions += 1;
            self.remember_ghost(fp);
            return true;
        }
        false
    }

    /// Pops the main FIFO: accessed entries are reinserted with freq-1, others die.
    fn evict_main(&mut self) -> bool {
        let mut rounds = self.main.len();
        while let Some((key, generation)) = self.main.pop_front() {
            let Some(node) = self.map.get_mut(&key) else {
                continue;
            };
            if node.generation != generation || !node.in_main {
                continue;
            }
            if node.freq > 0 && rounds > 0 {
                node.freq -= 1;
                rounds -= 1;
                self.main.push_back((key, generation));
                continue;
            }
            self.remove(&key);
            self.evictions += 1;
            return true;
        }
        false
    }

    fn remember_ghost(&mut self, fp: u64) {
        // Ghost holds about as many fingerprints as there are live entries.
        let cap = self.map.len().max(16);
        if self.ghost_set.insert(fp) {
            self.ghost.push_back(fp);
        }
        while self.ghost.len() > cap {
            if let Some(old) = self.ghost.pop_front() {
                self.ghost_set.remove(&old);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::RandomState;

    use super::*;

    fn cache(cap: usize) -> S3Fifo<u32, u32, RandomState> {
        S3Fifo::new(cap, 0, RandomState::new())
    }

    #[test]
    fn dns_006_respects_capacity_and_weights() {
        let mut c = cache(100);
        for i in 0..1000 {
            c.insert(i, i, 7);
            assert!(c.weight() <= 100);
        }
        assert!(c.len() <= 14);
        assert!(c.evictions() > 0);
    }

    #[test]
    fn dns_006_frequently_used_entries_survive_a_scan() {
        let mut c = cache(100);
        for i in 0..50 {
            c.insert(i, i, 1);
        }
        // Make 0..10 hot.
        for _ in 0..3 {
            for i in 0..10 {
                assert!(c.get_mut(&i).is_some());
            }
        }
        // One-hit-wonder scan much larger than the cache.
        for i in 1000..2000 {
            c.insert(i, i, 1);
        }
        let survivors = (0..10).filter(|i| c.peek(i).is_some()).count();
        assert_eq!(
            survivors, 10,
            "hot keys must survive a scan (S3-FIFO's main property)"
        );
    }

    #[test]
    fn dns_006_replace_and_remove_keep_weights_consistent() {
        let mut c = cache(1000);
        c.insert(1, 1, 10);
        c.insert(1, 2, 30);
        assert_eq!(c.weight(), 30);
        assert_eq!(c.peek(&1), Some(&2));
        assert_eq!(c.remove(&1), Some(2));
        assert_eq!(c.weight(), 0);
        c.insert(2, 2, 5);
        c.insert(3, 3, 5);
        c.retain(|k, _| *k == 3);
        assert_eq!(c.weight(), 5);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn dns_006_entry_cap() {
        let mut c: S3Fifo<u32, u32, RandomState> = S3Fifo::new(usize::MAX, 10, RandomState::new());
        for i in 0..100 {
            c.insert(i, i, 1);
        }
        assert!(c.len() <= 10);
    }
}
