//! Facts about the running host that every record carries.

use std::time::{SystemTime, UNIX_EPOCH};

fn proc_value(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Random per-boot identifier, ties records to one boot of the examination system.
pub fn boot_id() -> Option<String> {
    proc_value("/proc/sys/kernel/random/boot_id")
}

pub fn kernel_release() -> Option<String> {
    proc_value("/proc/sys/kernel/osrelease")
}

pub fn hostname() -> Option<String> {
    proc_value("/proc/sys/kernel/hostname")
}

pub fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail
    unsafe { libc::getuid() }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Nanoseconds since the Unix epoch, as `i128` so times before 1970 fit.
pub fn unix_now_ns() -> i128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

/// A file time as nanoseconds since the Unix epoch.
pub fn system_time_ns(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

/// Howard Hinnant's civil_from_days: (year, month, day) of a day count.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// Howard Hinnant's days_from_civil: the day count of (year, month, day).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn format_utc(secs: i64, fraction: Option<u32>) -> String {
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let tod = secs.rem_euclid(86_400);
    let frac = fraction.map(|ns| format!(".{ns:09}")).unwrap_or_default();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}Z",
        year,
        month,
        day,
        tod / 3_600,
        tod % 3_600 / 60,
        tod % 60,
        frac
    )
}

/// RFC 3339 UTC timestamp with second precision, e.g. `2026-10-11T14:46:52Z`.
pub fn rfc3339_utc(unix: u64) -> String {
    format_utc(unix as i64, None)
}

/// RFC 3339 UTC timestamp with nine fractional digits, e.g.
/// `2026-10-11T14:46:52.123456789Z`.
pub fn rfc3339_utc_ns(unix_ns: i128) -> String {
    let secs = unix_ns.div_euclid(1_000_000_000);
    let ns = unix_ns.rem_euclid(1_000_000_000) as u32;
    format_utc(secs as i64, Some(ns))
}

/// Parse an RFC 3339 timestamp (`2026-10-11T14:46:52Z`, `…T16:46:52.5+02:00`)
/// into nanoseconds since the Unix epoch. Strict: a date, `T`, a time, an
/// optional fraction of up to nine digits and a `Z` or `±hh:mm` offset are
/// required; a leap second (`:60`) is refused.
pub fn parse_rfc3339(s: &str) -> anyhow::Result<i128> {
    let bad =
        || anyhow::anyhow!("not an RFC 3339 timestamp: {s:?} (example: 2026-10-11T14:46:52Z)");
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> anyhow::Result<i64> {
        let part = b.get(from..from + len).ok_or_else(bad)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return Err(bad());
        }
        std::str::from_utf8(part)
            .map_err(|_| bad())?
            .parse()
            .map_err(|_| bad())
    };
    let sep = |at: usize, ch: &[u8]| -> anyhow::Result<()> {
        match b.get(at) {
            Some(c) if ch.contains(c) => Ok(()),
            _ => Err(bad()),
        }
    };
    let (year, month, day) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    sep(4, b"-")?;
    sep(7, b"-")?;
    sep(10, b"Tt")?;
    let (hour, minute, second) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    sep(13, b":")?;
    sep(16, b":")?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day < 1
        || day > month_days[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(bad());
    }
    let mut at = 19;
    let mut nanos: i64 = 0;
    if b.get(at) == Some(&b'.') {
        let digits = b[at + 1..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if digits == 0 || digits > 9 {
            return Err(bad());
        }
        nanos = num(at + 1, digits)? * 10_i64.pow((9 - digits) as u32);
        at += 1 + digits;
    }
    let offset_secs = match b.get(at) {
        Some(b'Z' | b'z') if b.len() == at + 1 => 0,
        Some(sign @ (b'+' | b'-')) if b.len() == at + 6 => {
            sep(at + 3, b":")?;
            let (oh, om) = (num(at + 1, 2)?, num(at + 4, 2)?);
            if oh > 23 || om > 59 {
                return Err(bad());
            }
            let off = oh * 3_600 + om * 60;
            if *sign == b'+' {
                off
            } else {
                -off
            }
        }
        _ => return Err(bad()),
    };
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
        - offset_secs;
    Ok(i128::from(secs) * 1_000_000_000 + i128::from(nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_791_730_012), "2026-10-11T14:46:52Z");
        assert_eq!(rfc3339_utc(4_107_542_399), "2100-02-28T23:59:59Z");
    }

    #[test]
    fn formats_nanoseconds_before_and_after_the_epoch() {
        assert_eq!(rfc3339_utc_ns(0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(
            rfc3339_utc_ns(1_791_730_012_123_456_789),
            "2026-10-11T14:46:52.123456789Z"
        );
        // Half a second before the epoch
        assert_eq!(
            rfc3339_utc_ns(-500_000_000),
            "1969-12-31T23:59:59.500000000Z"
        );
        // A FILETIME-era date: 1601-01-01
        assert_eq!(
            rfc3339_utc_ns(-11_644_473_600 * 1_000_000_000),
            "1601-01-01T00:00:00.000000000Z"
        );
    }

    #[test]
    fn parses_rfc3339_with_fraction_and_offset() {
        let t = 1_791_730_012 * 1_000_000_000_i128;
        assert_eq!(parse_rfc3339("2026-10-11T14:46:52Z").unwrap(), t);
        assert_eq!(parse_rfc3339("2026-10-11t14:46:52z").unwrap(), t);
        assert_eq!(parse_rfc3339("2026-10-11T16:46:52+02:00").unwrap(), t);
        assert_eq!(parse_rfc3339("2026-10-11T09:16:52-05:30").unwrap(), t);
        assert_eq!(
            parse_rfc3339("2026-10-11T14:46:52.5Z").unwrap(),
            t + 500_000_000
        );
        assert_eq!(
            parse_rfc3339("2026-10-11T14:46:52.123456789Z").unwrap(),
            t + 123_456_789
        );
        assert_eq!(
            parse_rfc3339("1969-12-31T23:59:59.5Z").unwrap(),
            -500_000_000
        );
        assert_eq!(
            parse_rfc3339("2000-02-29T00:00:00Z").unwrap(),
            951_782_400_000_000_000
        );
    }

    #[test]
    fn round_trips_formatted_timestamps() {
        for ns in [
            0,
            1,
            -1,
            951_782_400_000_000_007,
            -11_644_473_600_000_000_000,
        ] {
            assert_eq!(parse_rfc3339(&rfc3339_utc_ns(ns)).unwrap(), ns);
        }
    }

    #[test]
    fn refuses_anything_but_strict_rfc3339() {
        for s in [
            "",
            "2026-10-11",
            "2026-10-11 14:46:52Z",
            "2026-10-11T14:46:52",
            "2026-10-11T14:46:52+0200",
            "2026-10-11T14:46:52.Z",
            "2026-10-11T14:46:52.1234567891Z",
            "2026-13-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-10-11T24:00:00Z",
            "2026-10-11T14:46:60Z",
            "2026-10-11T14:46:52Z ",
            "+026-10-11T14:46:52Z",
            "2026-10-11T14:46:52+24:00",
        ] {
            assert!(parse_rfc3339(s).is_err(), "{s:?} was accepted");
        }
    }
}
