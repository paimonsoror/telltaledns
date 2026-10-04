//! Per-client query counts over fixed 10-minute windows: the input of the masked-client-IP
//! detector (REQ: OPS-003, `spec/08` §3.2). Updated on the aggregator thread only; bounded
//! by a client cap (clients past it count toward the total only).

use std::collections::HashMap;

/// Window length.
pub const WINDOW_SECS: u64 = 600;
/// Distinct clients counted per window.
const CAP: usize = 256;
/// Heaviest clients reported per window.
const REPORTED: usize = 4;

/// One window's totals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientWindow {
    /// Window start (Unix seconds).
    pub start_s: u64,
    /// Queries in the window.
    pub total: u64,
    /// Distinct clients seen (capped).
    pub clients: usize,
    /// The heaviest clients (v4-mapped) and their query counts, heaviest first.
    pub top: Vec<([u8; 16], u64)>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RecentClients {
    start_s: u64,
    total: u64,
    counts: HashMap<[u8; 16], u64>,
    done: Option<ClientWindow>,
}

impl RecentClients {
    pub(crate) fn add(&mut self, ip: [u8; 16], ts_s: u64) {
        let start = ts_s - ts_s % WINDOW_SECS;
        if start > self.start_s {
            if self.total > 0 {
                self.done = Some(self.summary());
            }
            self.start_s = start;
            self.total = 0;
            self.counts.clear();
        } else if start < self.start_s {
            return; // late event from a closed window
        }
        self.total += 1;
        if let Some(c) = self.counts.get_mut(&ip) {
            *c += 1;
        } else if self.counts.len() < CAP {
            self.counts.insert(ip, 1);
        }
    }

    fn summary(&self) -> ClientWindow {
        let mut top: Vec<([u8; 16], u64)> = self.counts.iter().map(|(k, v)| (*k, *v)).collect();
        top.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        top.truncate(REPORTED);
        ClientWindow {
            start_s: self.start_s,
            total: self.total,
            clients: self.counts.len(),
            top,
        }
    }

    /// The last complete window if it ended at most one window before `now_s`, else the
    /// window in progress if it's current. `None` when nothing recent was seen.
    pub(crate) fn latest(&self, now_s: u64) -> Option<ClientWindow> {
        let current = now_s - now_s % WINDOW_SECS;
        if let Some(d) = &self.done
            && d.start_s + WINDOW_SECS >= current.saturating_sub(WINDOW_SECS)
            && d.start_s < current
        {
            return Some(d.clone());
        }
        (self.total > 0 && self.start_s == current).then(|| self.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[10] = 0xff;
        a[11] = 0xff;
        a[12] = 10;
        a[15] = last;
        a
    }

    #[test]
    fn ops_003_windows_roll_and_expire() {
        let mut r = RecentClients::default();
        let t0 = 6000; // a window start
        for i in 0..90 {
            r.add(ip(1), t0 + i);
        }
        for i in 0..10 {
            r.add(ip(u8::try_from(i + 2).unwrap_or(0)), t0 + 100);
        }
        // In progress: reported while current.
        let w = r.latest(t0 + 300).unwrap_or_default();
        assert_eq!((w.total, w.clients), (100, 11));
        assert_eq!(w.top[0], (ip(1), 90));
        // Next window starts: the complete one is reported.
        r.add(ip(1), t0 + WINDOW_SECS + 5);
        let w = r.latest(t0 + WINDOW_SECS + 10).unwrap_or_default();
        assert_eq!((w.start_s, w.total), (t0, 100));
        // A late event from the closed window is ignored.
        r.add(ip(9), t0 + 1);
        assert_eq!(r.latest(t0 + WINDOW_SECS + 10).map(|w| w.total), Some(100));
        // Long silence: nothing is reported.
        assert_eq!(r.latest(t0 + 10 * WINDOW_SECS), None);
    }

    #[test]
    fn ops_003_client_cap_bounds_memory() {
        let mut r = RecentClients::default();
        for i in 0..1000u32 {
            let mut a = [0u8; 16];
            a[12..].copy_from_slice(&i.to_be_bytes());
            r.add(a, 600);
        }
        let w = r.latest(700).unwrap_or_default();
        assert_eq!((w.total, w.clients, w.top.len()), (1000, CAP, REPORTED));
    }
}
