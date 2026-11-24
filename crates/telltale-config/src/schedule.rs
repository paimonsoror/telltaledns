//! When a schedule is on (REQ: FLT-010, `spec/05` §3; T7.10).
//!
//! Windows are weekly: the days they start on and local start and end times, in the
//! schedule's time zone (the system tz database; the container image ships one). An end at or
//! before the start runs past midnight. The resolver asks [`Compiled::is_on`] from a 15-second
//! ticker, never per query.

use jiff::tz::TimeZone;

use crate::schema::{Config, ScheduleAction, ScheduleWindow};

/// A parsed window: start days (`0` = Monday) and minutes since midnight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    days: [bool; 7],
    start: u16,
    end: u16,
}

fn minutes(s: &str, allow_24: bool) -> Result<u16, String> {
    let (h, m) = s
        .split_once(':')
        .ok_or_else(|| format!("`{s}`: use HH:MM, e.g. 21:00"))?;
    let (h, m): (u16, u16) = (
        h.parse().map_err(|_| format!("`{s}`: use HH:MM"))?,
        m.parse().map_err(|_| format!("`{s}`: use HH:MM"))?,
    );
    let total = h * 60 + m;
    if m > 59 || total > 24 * 60 || (total == 24 * 60 && !allow_24) || h > 24 {
        return Err(format!("`{s}` isn't a time of day"));
    }
    Ok(total)
}

/// Parses one `[[schedule.window]]`.
pub fn parse_window(w: &ScheduleWindow) -> Result<Window, String> {
    let mut days = [false; 7];
    for d in &w.days {
        let set: &[usize] = match d.as_str().to_ascii_lowercase().as_str() {
            "mon" | "monday" => &[0],
            "tue" | "tuesday" => &[1],
            "wed" | "wednesday" => &[2],
            "thu" | "thursday" => &[3],
            "fri" | "friday" => &[4],
            "sat" | "saturday" => &[5],
            "sun" | "sunday" => &[6],
            "weekdays" => &[0, 1, 2, 3, 4],
            "weekends" => &[5, 6],
            "daily" | "everyday" => &[0, 1, 2, 3, 4, 5, 6],
            other => {
                return Err(format!(
                    "day `{other}`: use mon … sun, weekdays, weekends, or daily"
                ));
            }
        };
        for &i in set {
            days[i] = true;
        }
    }
    if !days.contains(&true) {
        return Err("`days` is empty".into());
    }
    Ok(Window {
        days,
        start: minutes(w.start.as_str(), false)?,
        end: minutes(w.end.as_str(), true)?,
    })
}

impl Window {
    /// Whether the window covers `minute` (since midnight) on `day` (`0` = Monday).
    pub fn contains(&self, day: usize, minute: u16) -> bool {
        let yesterday = (day + 6) % 7;
        if self.end > self.start {
            self.days[day] && (self.start..self.end).contains(&minute)
        } else {
            // Past midnight: from `start` on a listed day until `end` the next day.
            (self.days[day] && minute >= self.start) || (self.days[yesterday] && minute < self.end)
        }
    }
}

/// The time zone `name` (IANA), or the system's when `None` (UTC if it has none).
pub fn time_zone(name: Option<&str>) -> Result<TimeZone, String> {
    match name {
        Some(n) => TimeZone::get(n).map_err(|e| format!("time zone `{n}`: {e}")),
        None => Ok(TimeZone::try_system().unwrap_or(TimeZone::UTC)),
    }
}

/// REQ: CLU-014 (owner 2026-10-19) — the day of the month (1 to 7) `node`'s scheduled drill
/// falls on in `year`/`month`: picked from the three, so it moves around the first week and two
/// nodes rarely share it.
pub fn drill_day(node: &str, year: i16, month: i8) -> i8 {
    // FNV-1a: stable across builds and platforms.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in node
        .bytes()
        .chain(year.to_be_bytes())
        .chain(month.to_be_bytes())
    {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    i8::try_from(h % 7).unwrap_or(0) + 1
}

/// REQ: CLU-014 — the month (`year`, `month`) whose scheduled drill is due for `node` at `now`
/// (Unix seconds): during `[drill] hour` on that month's drill day, in `[drill] tz`. `None`
/// otherwise, or when the schedule is off.
pub fn drill_slot(cfg: &crate::schema::DrillConfig, node: &str, now: i64) -> Option<(i16, i8)> {
    if cfg.schedule != crate::schema::DrillSchedule::Monthly {
        return None;
    }
    let tz = time_zone(cfg.tz.as_ref().map(crate::types::SafeString::as_str)).ok()?;
    let z = jiff::Timestamp::from_second(now)
        .ok()?
        .to_zoned_datetime(tz);
    let (year, month) = (z.year(), z.month());
    (z.day() == drill_day(node, year, month) && i64::from(z.hour()) == i64::from(cfg.hour))
        .then_some((year, month))
}

/// A schedule ready to evaluate.
#[derive(Debug, Clone)]
pub struct Compiled {
    pub name: String,
    pub action: ScheduleAction,
    /// `enable_lists`: list names.
    pub lists: Vec<String>,
    /// `block_services`: service IDs.
    pub services: Vec<String>,
    tz: TimeZone,
    windows: Vec<Window>,
}

impl Compiled {
    /// Whether it's on at `now` (Unix seconds).
    pub fn is_on(&self, now: i64) -> bool {
        let Ok(ts) = jiff::Timestamp::from_second(now) else {
            return false;
        };
        let z = ts.to_zoned_datetime(self.tz.clone());
        let day = usize::try_from(z.weekday().to_monday_zero_offset()).unwrap_or(0);
        let minute = u16::try_from(i32::from(z.hour()) * 60 + i32::from(z.minute())).unwrap_or(0);
        self.windows.iter().any(|w| w.contains(day, minute))
    }

    /// Every list name it adds while on: its lists, and its services as `svc-` lists.
    pub fn list_names(&self) -> impl Iterator<Item = String> + '_ {
        self.lists
            .iter()
            .cloned()
            .chain(self.services.iter().map(|s| crate::services::list_name(s)))
    }
}

/// Every schedule in `cfg` that parses (validation reports the others).
pub fn compile(cfg: &Config) -> Vec<Compiled> {
    cfg.schedule
        .iter()
        .filter_map(|s| {
            Some(Compiled {
                name: s.name.to_string(),
                action: s.action,
                lists: s.lists.iter().map(ToString::to_string).collect(),
                services: s.services.iter().map(ToString::to_string).collect(),
                tz: time_zone(s.tz.as_ref().map(crate::types::SafeString::as_str)).ok()?,
                windows: s
                    .window
                    .iter()
                    .map(parse_window)
                    .collect::<Result<_, _>>()
                    .ok()?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SafeString;

    fn w(days: &[&str], start: &str, end: &str) -> ScheduleWindow {
        ScheduleWindow {
            days: days.iter().map(|d| SafeString::new(*d).unwrap()).collect(),
            start: SafeString::new(start).unwrap(),
            end: SafeString::new(end).unwrap(),
        }
    }

    /// REQ: FLT-010 — windows within a day and past midnight, named day sets, bad input.
    #[test]
    fn flt_010_windows() {
        let school = parse_window(&w(&["weekdays"], "08:00", "15:00")).unwrap();
        assert!(school.contains(0, 8 * 60));
        assert!(!school.contains(0, 15 * 60), "the end is exclusive");
        assert!(!school.contains(5, 9 * 60), "not on Saturday");
        let night = parse_window(&w(&["sun", "mon"], "21:00", "07:00")).unwrap();
        assert!(night.contains(6, 22 * 60), "Sunday night");
        assert!(
            night.contains(0, 6 * 60),
            "early Monday, from Sunday's window"
        );
        assert!(
            night.contains(1, 6 * 60),
            "early Tuesday, from Monday's window"
        );
        assert!(!night.contains(2, 6 * 60), "Tuesday has no window");
        assert!(!night.contains(0, 12 * 60));
        let all_day = parse_window(&w(&["daily"], "00:00", "24:00")).unwrap();
        assert!(all_day.contains(3, 0) && all_day.contains(3, 1439));
        assert!(parse_window(&w(&["someday"], "08:00", "09:00")).is_err());
        assert!(parse_window(&w(&["mon"], "8", "09:00")).is_err());
        assert!(parse_window(&w(&["mon"], "24:00", "09:00")).is_err());
        assert!(parse_window(&w(&["mon"], "08:60", "09:00")).is_err());
    }

    /// REQ: FLT-010 — the schedule's own time zone decides (UTC always exists).
    // REQ: CLU-014 — a monthly drill: one hour on one day in the first week, the same for a node
    // and month, at the configured hour in the configured zone; never when the schedule is off.
    #[test]
    fn clu_014_drill_slot() {
        use crate::schema::{DrillConfig, DrillSchedule};
        let cfg = DrillConfig {
            schedule: DrillSchedule::Monthly,
            hour: 3,
            tz: Some(SafeString::from("UTC")),
            ..DrillConfig::default()
        };
        let day = drill_day("home-pi", 2026, 11);
        assert!((1..=7).contains(&day));
        assert_eq!(day, drill_day("home-pi", 2026, 11), "stable");
        let days: std::collections::HashSet<i8> =
            (1..=12).map(|m| drill_day("home-pi", 2026, m)).collect();
        assert!(days.len() > 1, "it moves around the first week");
        let at = |d: i8, h: i8| {
            jiff::civil::date(2026, 11, d)
                .at(h, 30, 0, 0)
                .to_zoned_datetime(TimeZone::UTC)
                .unwrap()
                .timestamp()
                .as_second()
        };
        assert_eq!(drill_slot(&cfg, "home-pi", at(day, 3)), Some((2026, 11)));
        assert_eq!(
            drill_slot(&cfg, "home-pi", at(day, 4)),
            None,
            "another hour"
        );
        let other = if day == 7 { 1 } else { day + 1 };
        assert_eq!(
            drill_slot(&cfg, "home-pi", at(other, 3)),
            None,
            "another day"
        );
        let off = DrillConfig::default();
        assert_eq!(drill_slot(&off, "home-pi", at(day, 3)), None, "off");
    }

    #[test]
    fn flt_010_time_zone() {
        assert!(time_zone(Some("Mars/Olympus_Mons")).is_err());
        let s = Compiled {
            name: "t".into(),
            action: ScheduleAction::BlockAll,
            lists: Vec::new(),
            services: Vec::new(),
            tz: TimeZone::UTC,
            windows: vec![parse_window(&w(&["mon"], "10:00", "11:00")).unwrap()],
        };
        // 2026-10-05 is a Monday: 10:30 UTC is on, 11:30 isn't.
        let monday_1030 = 1_791_196_200;
        assert!(s.is_on(monday_1030));
        assert!(!s.is_on(monday_1030 + 3600));
    }

    /// A one-window schedule in the system database's zone `tz`. `None` (the test says it
    /// skipped) only where there is no time zone database at all: jiff found none in `TZDIR`,
    /// `/usr/share/zoneinfo`, `/usr/share/lib/zoneinfo` or `/etc/zoneinfo`. With one, any lookup
    /// error (a zone it can't find or refuses to read) fails the test.
    fn in_zone(tz: &str, window: &ScheduleWindow) -> Option<Compiled> {
        if jiff::tz::db().is_definitively_empty() {
            eprintln!("skipped: no system time zone database here");
            return None;
        }
        let tz = time_zone(Some(tz)).unwrap();
        Some(Compiled {
            name: "dst".into(),
            action: ScheduleAction::BlockAll,
            lists: Vec::new(),
            services: Vec::new(),
            tz,
            windows: vec![parse_window(window).unwrap()],
        })
    }

    /// REQ: FLT-010 — the DST tests below skip only where there is no time zone database at all:
    /// with one, a zone lookup that fails (here a zone that doesn't exist) fails them instead of
    /// passing as a skip.
    #[test]
    fn flt_010_dst_tests_fail_on_a_lookup_error_when_a_database_exists() {
        if jiff::tz::db().is_definitively_empty() {
            eprintln!("skipped: no system time zone database here");
            return;
        }
        let lookup = std::panic::catch_unwind(|| {
            in_zone("Mars/Olympus_Mons", &w(&["sun"], "02:00", "03:00"))
        });
        assert!(
            lookup.is_err(),
            "an unknown zone must fail the test, not skip it"
        );
    }

    /// The spans `[on, off)` (Unix seconds) in which `s` is on, checked every minute of `[from, to)`.
    fn on_spans(s: &Compiled, from: i64, to: i64) -> Vec<(i64, i64)> {
        let (mut spans, mut on) = (Vec::new(), None);
        for t in (from..to).step_by(60) {
            match (s.is_on(t), on) {
                (true, None) => on = Some(t),
                (false, Some(a)) => {
                    spans.push((a, t));
                    on = None;
                }
                _ => {}
            }
        }
        spans.extend(on.map(|a| (a, to)));
        spans
    }

    /// REQ: FLT-010 — a window is local wall-clock time across daylight saving changes, here
    /// `America/New_York`'s in 2026 (Sunday 8 March 02:00 EST -> 03:00 EDT, Sunday 1 November
    /// 02:00 EDT -> 01:00 EST): on the spring day it covers only the local minutes that exist, on
    /// the autumn day it covers the repeated hour twice. The instants are written out by hand.
    #[test]
    fn flt_010_dst_spring_forward_and_fall_back_in_new_york() {
        // 01:30 to 03:30 on 8 March: on at 01:30 EST (06:30Z), off at 03:30 EDT (07:30Z): one
        // hour, not two (02:00 to 02:59 doesn't exist). Checked 04:00Z to 10:00Z.
        let Some(spring) = in_zone("America/New_York", &w(&["sun"], "01:30", "03:30")) else {
            return;
        };
        assert_eq!(
            on_spans(&spring, 1_772_942_400, 1_772_964_000),
            [(1_772_951_400, 1_772_955_000)]
        );
        // 01:30 to 02:30 on 1 November: on at 01:30 EDT (05:30Z); at 06:00Z it is 01:00 EST,
        // off until 01:30 EST (06:30Z), then on until 02:30 EST (07:30Z). Checked 04:00Z to 10:00Z.
        let Some(autumn) = in_zone("America/New_York", &w(&["sun"], "01:30", "02:30")) else {
            return;
        };
        assert_eq!(
            on_spans(&autumn, 1_793_505_600, 1_793_527_200),
            [
                (1_793_511_000, 1_793_512_800),
                (1_793_514_600, 1_793_518_200)
            ]
        );
    }

    /// REQ: FLT-010 — the same with a half-hour offset and a half-hour change:
    /// `Australia/Lord_Howe` is +10:30 in winter and +11:00 in summer. In 2026 it goes back on
    /// Sunday 5 April (02:00 +11:00 -> 01:30 +10:30, at 15:00Z on the 4th) and forward on Sunday
    /// 4 October (02:00 +10:30 -> 02:30 +11:00, at 15:30Z on the 3rd): the local day is a UTC day
    /// ahead.
    #[test]
    fn flt_010_dst_half_hour_change_on_lord_howe() {
        // 01:45 to 02:15 on 5 April: on at 01:45 +11:00 (14:45Z); at 15:00Z it is 01:30 +10:30,
        // off until 01:45 +10:30 (15:15Z), then on until 02:15 +10:30 (15:45Z). Checked 12:00Z
        // to 18:00Z on the 4th.
        let Some(autumn) = in_zone("Australia/Lord_Howe", &w(&["sun"], "01:45", "02:15")) else {
            return;
        };
        assert_eq!(
            on_spans(&autumn, 1_775_304_000, 1_775_325_600),
            [
                (1_775_313_900, 1_775_314_800),
                (1_775_315_700, 1_775_317_500)
            ]
        );
        // 02:00 to 03:00 on 4 October: 01:59 +10:30 (15:29Z) is followed by 02:30 +11:00
        // (15:30Z), so it is on from 15:30Z to 03:00 +11:00 (16:00Z), half an hour. Checked 12:00Z
        // to 18:00Z on the 3rd.
        let Some(spring) = in_zone("Australia/Lord_Howe", &w(&["sun"], "02:00", "03:00")) else {
            return;
        };
        assert_eq!(
            on_spans(&spring, 1_791_028_800, 1_791_050_400),
            [(1_791_041_400, 1_791_043_200)]
        );
        // A window wholly inside the skipped half hour is never on that day.
        let Some(gap) = in_zone("Australia/Lord_Howe", &w(&["sun"], "02:00", "02:30")) else {
            return;
        };
        let never: [(i64, i64); 0] = [];
        assert_eq!(on_spans(&gap, 1_791_028_800, 1_791_050_400), never);
    }
}
