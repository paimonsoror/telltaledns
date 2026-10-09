//! REQ: OBS-016 (T11.1, ADR-105, `spec/06` §8.2) — service-level objectives, their error
//! budgets, and burn rates, from the time buckets every node already keeps (federated in a
//! cluster, so the objectives cover every node's answers).
//!
//! Two objectives, each a share of *answered* queries (dropped ones got no answer to judge):
//! - **availability:** answers that aren't SERVFAIL;
//! - **latency:** answers sent within `[slo] latency_ms` (the time buckets count the slower
//!   ones as `slow`).
//!
//! The burn rate over a window is the bad share divided by the share the target allows: 1
//! spends the budget exactly over the objective's window, 14.4 spends a 30-day budget's 2% in
//! an hour. Alerts pair a long and a short window, as the Google SRE workbook does, so they
//! start quickly and stop soon after the problem does: `fast` (14.4× over 1 h and 5 min),
//! `slow` (6× over 6 h and 30 min), and `ticket` (1× over 3 days and 6 h, shown but never
//! alerted). Small networks see a SERVFAIL among few queries often, so a pair also needs
//! [`MIN_ANSWERED`] answers in its short window and [`MIN_BAD`] bad ones in its long window.
//!
//! Pure functions over buckets: nothing here reads the clock or touches the query path.

use std::fmt::Write as _;

use crate::model::{SloBurn, SloObjective, SloStatus, TimeBucket};

/// The objectives as configured (`[slo]`).
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    /// Percent of answers that must not be SERVFAIL.
    pub availability_target: f64,
    /// Percent of answers that must arrive within `latency_ms`.
    pub latency_target: f64,
    pub latency_ms: u32,
    pub window_days: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            availability_target: 99.9,
            latency_target: 99.0,
            latency_ms: 250,
            window_days: 30,
        }
    }
}

/// Burn-rate windows: seconds and label.
pub const WINDOWS: [(u64, &str); 5] = [
    (300, "5m"),
    (1800, "30m"),
    (3600, "1h"),
    (6 * 3600, "6h"),
    (3 * 86_400, "3d"),
];
/// The longest window read from minute buckets (the rest come from hour buckets).
pub const MINUTE_SPAN_S: u64 = 6 * 3600;
/// Burn rates that alert: (name, long window, short window, rate).
pub const ALERTS: [(&str, &str, &str, f64); 3] = [
    ("fast", "1h", "5m", 14.4),
    ("slow", "6h", "30m", 6.0),
    ("ticket", "3d", "6h", 1.0),
];
/// A window pair alerts only with at least this many answers in its short window...
pub const MIN_ANSWERED: u64 = 50;
/// ...and this many bad answers in its long window.
pub const MIN_BAD: u64 = 10;

/// Which objective a bucket is judged for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Availability,
    Latency,
}

/// Answered queries in `b`, and how many of them were bad for `kind`. The same events the
/// Prometheus rules count: availability over responses (every RCODE, as
/// `telltale_responses_total`), latency over queries with a timing (all but `dropped`, as
/// `telltale_query_duration_seconds_count`).
fn tally(b: &TimeBucket, kind: Kind) -> (u64, u64) {
    let (answered, bad) = match kind {
        Kind::Availability => (
            b.by_rcode.values().map(|n| u64::from(*n)).sum(),
            b.by_rcode.get("SERVFAIL").copied().unwrap_or(0),
        ),
        Kind::Latency => {
            let dropped = b.by_status.get("dropped").copied().unwrap_or(0);
            (u64::from(b.total.saturating_sub(dropped)), b.slow)
        }
    };
    (answered, u64::from(bad).min(answered))
}

/// Answers and bad answers in buckets starting at or after `from_s`.
fn sum(buckets: &[TimeBucket], from_s: u64, kind: Kind) -> (u64, u64) {
    buckets
        .iter()
        .filter(|b| b.start_unix_seconds >= from_s)
        .map(|b| tally(b, kind))
        .fold((0, 0), |(t, x), (a, b)| (t + a, x + b))
}

#[allow(clippy::cast_precision_loss)] // query counts as shares
fn share(bad: u64, total: u64) -> Option<f64> {
    (total > 0).then(|| bad as f64 / total as f64)
}

/// Every objective at `now`. `minutes` should cover the last [`MINUTE_SPAN_S`] seconds and
/// `hours` the budget window (`window_days`); with `hours` empty, the 3-day rate and the budget
/// are unknown, which is all [`burning`] needs.
pub fn status(s: &Settings, now: u64, minutes: &[TimeBucket], hours: &[TimeBucket]) -> SloStatus {
    if !s.enabled {
        return SloStatus {
            enabled: false,
            window_days: s.window_days,
            ..SloStatus::default()
        };
    }
    SloStatus {
        enabled: true,
        window_days: s.window_days,
        objectives: vec![
            objective(s, Kind::Availability, now, minutes, hours),
            objective(s, Kind::Latency, now, minutes, hours),
        ],
        missing_nodes: Vec::new(),
    }
}

/// The objectives whose budget burns fast enough to alert (`fast` or `slow`), from minute
/// buckets alone: `(objective, alert, summary)`.
pub fn burning(s: &Settings, now: u64, minutes: &[TimeBucket]) -> Vec<(String, String, String)> {
    status(s, now, minutes, &[])
        .objectives
        .into_iter()
        .filter_map(|o| {
            let a = o.alert.clone().filter(|a| a != "ticket")?;
            let &(_, long, short, _) = ALERTS.iter().find(|(n, ..)| *n == a)?;
            let r = |w: &str| {
                o.burn_rates
                    .iter()
                    .find(|b| b.window == w)
                    .and_then(|b| b.rate)
                    .unwrap_or(0.0)
            };
            let summary = format!(
                "the {} objective ({}% {}) is spending its error budget {:.1}× too fast over the last {long} ({:.1}× over {short})",
                o.name,
                o.target_percent,
                o.good_means,
                r(long),
                r(short)
            );
            Some((o.name, a, summary))
        })
        .collect()
}

fn objective(
    s: &Settings,
    kind: Kind,
    now: u64,
    minutes: &[TimeBucket],
    hours: &[TimeBucket],
) -> SloObjective {
    let (name, target, good_means) = match kind {
        Kind::Availability => (
            "availability",
            s.availability_target,
            "answers that aren't SERVFAIL".to_owned(),
        ),
        Kind::Latency => (
            "latency",
            s.latency_target,
            format!("answers sent within {} ms", s.latency_ms),
        ),
    };
    let allowed = (1.0 - target / 100.0).max(f64::EPSILON);
    let burn_rates: Vec<SloBurn> = WINDOWS
        .iter()
        .map(|&(secs, label)| {
            let from = now.saturating_sub(secs);
            // Hour buckets start on the hour: take the hour the window starts in, so a 3-day
            // window covers at least 3 days.
            let (total, bad) = if secs <= MINUTE_SPAN_S {
                sum(minutes, from, kind)
            } else {
                sum(hours, from - from % 3600, kind)
            };
            SloBurn {
                window: label.to_owned(),
                rate: if secs > MINUTE_SPAN_S && hours.is_empty() {
                    None
                } else {
                    share(bad, total).map(|x| round2(x / allowed))
                },
                total,
                bad,
            }
        })
        .collect();
    let rate = |w: &str| burn_rates.iter().find(|b| b.window == w);
    let alert = ALERTS
        .iter()
        .find(|&&(_, long, short, threshold)| {
            let (Some(l), Some(sh)) = (rate(long), rate(short)) else {
                return false;
            };
            l.rate.is_some_and(|r| r >= threshold)
                && sh.rate.is_some_and(|r| r >= threshold)
                && sh.total >= MIN_ANSWERED
                && l.bad >= MIN_BAD
        })
        .map(|(a, ..)| (*a).to_owned());
    let window_s = u64::from(s.window_days) * 86_400;
    let (total, bad) = if hours.is_empty() {
        (0, 0)
    } else {
        let from = now.saturating_sub(window_s);
        sum(hours, from - from % 3600, kind)
    };
    let sli = share(total - bad, total);
    let remaining = share(bad, total).map(|x| round2(100.0 * (1.0 - x / allowed)));
    let summary = summarize(
        name,
        &good_means,
        target,
        s.window_days,
        sli,
        total,
        remaining,
        alert.as_deref(),
        &burn_rates,
    );
    SloObjective {
        name: name.to_owned(),
        good_means,
        target_percent: target,
        latency_ms: (kind == Kind::Latency).then_some(s.latency_ms),
        sli_percent: sli.map(|x| round3(x * 100.0)),
        good: total - bad,
        total,
        budget_remaining_percent: remaining,
        burn_rates,
        alert,
        summary,
    }
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// One sentence with the numbers.
#[allow(clippy::too_many_arguments)]
fn summarize(
    name: &str,
    good_means: &str,
    target: f64,
    window_days: u32,
    sli: Option<f64>,
    total: u64,
    remaining: Option<f64>,
    alert: Option<&str>,
    burns: &[SloBurn],
) -> String {
    let mut out = match (sli, remaining) {
        (Some(sli), Some(left)) => format!(
            "{name}: {:.3}% of {total} answers in the last {window_days} days were {good_means} (target {target}%); {left:.0}% of the error budget is left.",
            sli * 100.0
        ),
        _ => format!("{name}: target {target}% {good_means}; no answers to judge yet."),
    };
    let pair = alert.and_then(|a| ALERTS.iter().find(|(n, ..)| *n == a));
    if let Some(&(_, long, short, _)) = pair {
        let r = |w: &str| {
            burns
                .iter()
                .find(|b| b.window == w)
                .and_then(|b| b.rate)
                .unwrap_or(0.0)
        };
        let lasts = remaining
            .filter(|l| *l > 0.0 && r(long) > 0.0)
            .map(|l| {
                format!(
                    " At this rate the rest of the budget lasts {:.1} days.",
                    l / 100.0 * f64::from(window_days) / r(long)
                )
            })
            .unwrap_or_default();
        let _ = write!(
            out,
            " Spending the budget {:.1}× too fast over the last {long} ({:.1}× over {short}).{lasts}",
            r(long),
            r(short)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Half past an hour (1,800,000,000 is on the hour).
    const NOW: u64 = 1_800_001_800;

    /// A bucket at `start` with `total` answers, `servfail` SERVFAILs, `slow` slow ones.
    fn bucket(start: u64, total: u32, servfail: u32, slow: u32) -> TimeBucket {
        let mut b = TimeBucket {
            start_unix_seconds: start,
            total,
            slow,
            ..TimeBucket::default()
        };
        b.by_rcode.insert("NOERROR".into(), total - servfail);
        if servfail > 0 {
            b.by_rcode.insert("SERVFAIL".into(), servfail);
        }
        b
    }

    /// Minute buckets for the last `mins` minutes, each with these counts.
    fn minutes(mins: u64, total: u32, servfail: u32, slow: u32) -> Vec<TimeBucket> {
        (1..=mins)
            .map(|m| bucket(NOW - NOW % 60 - (m - 1) * 60, total, servfail, slow))
            .collect()
    }

    fn hours(n: u64, total: u32, servfail: u32, slow: u32) -> Vec<TimeBucket> {
        (0..n)
            .map(|h| bucket(NOW - NOW % 3600 - h * 3600, total, servfail, slow))
            .collect()
    }

    fn get<'a>(st: &'a SloStatus, name: &str) -> &'a SloObjective {
        st.objectives.iter().find(|o| o.name == name).unwrap()
    }

    fn rate(o: &SloObjective, w: &str) -> Option<f64> {
        o.burn_rates.iter().find(|b| b.window == w).unwrap().rate
    }

    // REQ: OBS-016 — a clean month: SLIs, untouched budgets, burn 0, no alert.
    #[test]
    fn obs_016_clean_month() {
        let st = status(
            &Settings::default(),
            NOW,
            &minutes(360, 100, 0, 0),
            &hours(720, 6000, 0, 0),
        );
        assert!(st.enabled);
        for o in &st.objectives {
            assert_eq!(o.sli_percent, Some(100.0), "{}", o.name);
            assert_eq!(o.budget_remaining_percent, Some(100.0));
            assert_eq!(rate(o, "1h"), Some(0.0));
            assert_eq!(o.alert, None);
        }
        assert_eq!(get(&st, "latency").latency_ms, Some(250));
        assert_eq!(get(&st, "availability").total, 720 * 6000);
    }

    // REQ: OBS-016 — burn = bad share ÷ allowed share; budget left = 1 − burn over the window.
    #[test]
    fn obs_016_burn_rates_and_budget() {
        // 0.05% SERVFAIL all month against 99.9%: burn 0.5, half the budget left.
        let st = status(
            &Settings::default(),
            NOW,
            &minutes(360, 2000, 1, 0),
            &hours(720, 20_000, 10, 0),
        );
        let a = get(&st, "availability");
        assert_eq!(rate(a, "1h"), Some(0.5));
        assert_eq!(rate(a, "3d"), Some(0.5));
        assert_eq!(a.budget_remaining_percent, Some(50.0));
        assert_eq!(a.sli_percent, Some(99.95));
        assert_eq!(a.alert, None);
        // Only the window counts: hours before it are ignored.
        let mut long = hours(720, 20_000, 10, 0);
        long.extend(hours(2000, 1, 1, 0).into_iter().skip(800));
        let st = status(&Settings::default(), NOW, &minutes(1, 1, 0, 0), &long);
        assert_eq!(
            get(&st, "availability").budget_remaining_percent,
            Some(50.0)
        );
    }

    // REQ: OBS-016 — the window pairs: fast (14.4× over 1 h and 5 min), slow (6× over 6 h and
    // 30 min), ticket (1× over 3 days and 6 h).
    #[test]
    fn obs_016_alert_pairs() {
        let s = Settings::default();
        // 2% SERVFAIL for the last hour (burn 20): fast.
        let mut m = minutes(360, 1000, 0, 0);
        for b in m.iter_mut().take(60) {
            b.by_rcode.insert("SERVFAIL".into(), 20);
        }
        let st = status(&s, NOW, &m, &hours(720, 1000, 0, 0));
        assert_eq!(get(&st, "availability").alert.as_deref(), Some("fast"));
        assert!(
            get(&st, "availability")
                .summary
                .contains("too fast over the last 1h"),
            "{}",
            get(&st, "availability").summary
        );
        assert_eq!(get(&st, "latency").alert, None, "objectives are separate");
        // The problem stopped 10 minutes ago: the short window clears the alert.
        let mut m2 = m.clone();
        for b in m2.iter_mut().take(10) {
            b.by_rcode.clear();
        }
        let st = status(&s, NOW, &m2, &[]);
        assert_eq!(get(&st, "availability").alert, None);
        // 0.7% SERVFAIL for 6 hours (burn 7): slow.
        let st = status(&s, NOW, &minutes(360, 1000, 7, 0), &[]);
        assert_eq!(get(&st, "availability").alert.as_deref(), Some("slow"));
        // 0.15% for 3 days (burn 1.5): ticket, which `burning` leaves out.
        let st = status(
            &s,
            NOW,
            &minutes(360, 2000, 3, 0),
            &hours(80, 100_000, 150, 0),
        );
        assert_eq!(get(&st, "availability").alert.as_deref(), Some("ticket"));
        assert_eq!(
            burning(&s, NOW, &minutes(360, 2000, 3, 0)),
            Vec::<(String, String, String)>::new()
        );
        // Slow answers drive the latency objective the same way.
        let b = burning(&s, NOW, &minutes(360, 1000, 0, 200));
        assert_eq!(b.len(), 1);
        assert_eq!((b[0].0.as_str(), b[0].1.as_str()), ("latency", "fast"));
    }

    // REQ: OBS-016 (ADR-105) — a few bad answers on a quiet network don't alert, and dropped
    // queries count for neither objective.
    #[test]
    fn obs_016_quiet_networks_and_dropped_queries() {
        let s = Settings::default();
        // 5 queries a minute, one SERVFAIL every 5 minutes: burn 40, but 5 bad in the hour.
        let mut m = minutes(360, 5, 0, 0);
        for b in m.iter_mut().step_by(5).take(5) {
            b.by_rcode.insert("SERVFAIL".into(), 1);
        }
        let st = status(&s, NOW, &m, &[]);
        assert!(rate(get(&st, "availability"), "1h").unwrap() > 14.4);
        assert_eq!(get(&st, "availability").alert, None, "too few to judge");
        // Dropped queries aren't answers (no RCODE, no timing).
        let mut b = bucket(NOW - NOW % 60, 100, 0, 0);
        b.by_status.insert("dropped".into(), 100);
        b.by_rcode.clear();
        let st = status(&s, NOW, &[b], &[]);
        assert_eq!(get(&st, "availability").burn_rates[0].total, 0);
        assert_eq!(get(&st, "latency").burn_rates[0].total, 0);
        assert_eq!(rate(get(&st, "availability"), "5m"), None);
        // Off: nothing.
        let off = Settings {
            enabled: false,
            ..s
        };
        let st = status(&off, NOW, &m, &[]);
        assert!(!st.enabled);
        assert!(st.objectives.is_empty());
    }
}
