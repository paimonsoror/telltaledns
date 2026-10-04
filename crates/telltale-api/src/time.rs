//! `from` / `to` parameters (`spec/07` §1): RFC 3339 (`2026-10-03T12:00:00Z`, offsets
//! allowed) or relative to now (`-24h`, `-15m`, `-30s`, `-7d`, `now`).

/// Seconds since the Unix epoch for a time parameter, relative to `now_s`.
pub fn parse_time(text: &str, now_s: u64) -> Result<u64, String> {
    let t = text.trim();
    if t.is_empty() || t == "now" {
        return Ok(now_s);
    }
    if let Some(rel) = t.strip_prefix('-') {
        let (num, unit) =
            rel.split_at(rel.find(|c: char| !c.is_ascii_digit()).unwrap_or(rel.len()));
        let n: u64 = num
            .parse()
            .map_err(|_| format!("`{t}`: expected a number before the unit"))?;
        let secs = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            _ => return Err(format!("`{t}`: unit must be s, m, h, or d")),
        };
        return Ok(now_s.saturating_sub(n.saturating_mul(secs)));
    }
    rfc3339(t).ok_or_else(|| {
        format!("`{t}`: expected RFC 3339 time (2026-10-03T12:00:00Z) or a relative offset (-24h)")
    })
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)` to Unix seconds.
fn rfc3339(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(r)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't' | b' ')
    {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &frac[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6
            && matches!(rest.as_bytes()[0], b'+' | b'-')
            && rest.as_bytes()[3] == b':' =>
        {
            let oh: i64 = rest.get(1..3)?.parse().ok()?;
            let om: i64 = rest.get(4..6)?.parse().ok()?;
            let v = oh * 3600 + om * 60;
            if rest.starts_with('-') { -v } else { v }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    u64::try_from(secs).ok()
}
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// RFC 3339 UTC with milliseconds for Unix microseconds.
pub fn format_us(us: u64) -> String {
    let secs = i64::try_from(us / 1_000_000).unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        sod / 3600,
        sod / 60 % 60,
        sod % 60,
        us / 1000 % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_001_time_parameters() {
        let now = 1_791_072_000; // 2026-10-04T00:00:00Z
        assert_eq!(parse_time("now", now), Ok(now));
        assert_eq!(parse_time("-24h", now), Ok(now - 86_400));
        assert_eq!(parse_time("-15m", now), Ok(now - 900));
        assert_eq!(parse_time("-7d", now), Ok(now - 7 * 86_400));
        assert_eq!(parse_time("2026-10-04T00:00:00Z", now), Ok(now));
        assert_eq!(parse_time("2026-10-04T02:00:00+02:00", now), Ok(now));
        assert_eq!(parse_time("2026-10-03T23:00:00.123-01:00", now), Ok(now));
        for bad in [
            "-24x",
            "yesterday",
            "2026-13-01T00:00:00Z",
            "2026-10-04T00:00:00",
            "-h",
        ] {
            assert!(parse_time(bad, now).is_err(), "{bad}");
        }
        assert_eq!(format_us(1_791_072_000_123_456), "2026-10-04T00:00:00.123Z");
    }
}
