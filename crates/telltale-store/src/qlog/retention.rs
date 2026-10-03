//! Retention (OBS-003): by age and by total size, oldest segments first.

use std::io;
use std::path::Path;

use super::list_segments;

/// Deletes segments older than `days` (by hour) and then the oldest ones until the total is
/// within `max_bytes`. Never deletes `current` (the part being written). Empty date
/// directories left behind are removed. Returns the number of segments deleted.
pub fn enforce(
    dir: &Path,
    now_hour: u64,
    days: u32,
    max_bytes: u64,
    current: Option<&Path>,
) -> io::Result<usize> {
    let mut segs: Vec<_> = list_segments(dir)?
        .into_iter()
        .filter(|(_, p)| Some(p.as_path()) != current)
        .filter_map(|(id, p)| Some((id, std::fs::metadata(&p).ok()?.len(), p)))
        .collect();
    segs.sort_by_key(|(id, _, _)| *id);
    let oldest_kept = now_hour.saturating_sub(u64::from(days) * 24);
    let current_len = current
        .and_then(|p| std::fs::metadata(p).ok())
        .map_or(0, |m| m.len());
    let mut total: u64 = segs.iter().map(|(_, len, _)| len).sum::<u64>() + current_len;
    let mut removed = 0;
    for (id, len, path) in &segs {
        if id.hour >= oldest_kept && total <= max_bytes {
            break;
        }
        match std::fs::remove_file(path) {
            Ok(()) => {
                removed += 1;
                total = total.saturating_sub(*len);
                // Remove DD, MM, YYYY directories once empty (errors mean "not empty").
                let mut d = path.parent();
                for _ in 0..3 {
                    let Some(p) = d else { break };
                    if p == dir || std::fs::remove_dir(p).is_err() {
                        break;
                    }
                    d = p.parent();
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}
