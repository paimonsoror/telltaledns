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
        let z = ts.to_zoned(self.tz.clone());
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
}
