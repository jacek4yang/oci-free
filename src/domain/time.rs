//! The small amount of calendar arithmetic this product needs.
//!
//! Two commands need real dates: `cost` has to name the current billing period
//! in RFC 3339, and several reports show how old something is. That is not
//! enough to justify a date-time dependency, so the civil-date conversion is
//! implemented here — it is a well-known closed-form algorithm, it is fully
//! tested below, and it keeps the dependency surface of a security-sensitive
//! CLI smaller.
//!
//! Everything is UTC. OCI timestamps are UTC and billing periods are defined in
//! UTC, so introducing a local timezone would only create ways to be wrong.

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

/// Seconds in a day.
const DAY: i64 = 86_400;

/// A UTC instant at one-second resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct UtcDateTime {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl UtcDateTime {
    /// The current time, or the epoch if the host clock is before 1970.
    #[must_use]
    pub fn now() -> Self {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
            });
        Self::from_unix(seconds)
    }

    /// Convert from a Unix timestamp.
    #[must_use]
    pub fn from_unix(seconds: i64) -> Self {
        let days = seconds.div_euclid(DAY);
        let rest = seconds.rem_euclid(DAY);
        let (year, month, day) = civil_from_days(days);
        Self {
            year,
            month,
            day,
            hour: u32::try_from(rest / 3600).unwrap_or(0),
            minute: u32::try_from((rest % 3600) / 60).unwrap_or(0),
            second: u32::try_from(rest % 60).unwrap_or(0),
        }
    }

    /// Seconds since the Unix epoch.
    #[must_use]
    pub fn to_unix(self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * DAY
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }

    /// Midnight UTC on the first day of this month.
    #[must_use]
    pub fn start_of_month(self) -> Self {
        Self {
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            ..self
        }
    }

    /// Midnight UTC on the first day of the following month.
    #[must_use]
    pub fn start_of_next_month(self) -> Self {
        let (year, month) = if self.month >= 12 {
            (self.year + 1, 1)
        } else {
            (self.year, self.month + 1)
        };
        Self {
            year,
            month,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        }
    }

    /// Midnight UTC at the start of this day.
    #[must_use]
    pub fn start_of_day(self) -> Self {
        Self {
            hour: 0,
            minute: 0,
            second: 0,
            ..self
        }
    }

    /// RFC 3339 with a `Z` suffix, which is what the Usage API expects.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// Just the date, `YYYY-MM-DD`.
    #[must_use]
    pub fn to_date(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// Parse an RFC 3339 timestamp of the form OCI emits.
    ///
    /// Deliberately narrow: it accepts `YYYY-MM-DDTHH:MM:SS` followed by an
    /// optional fractional part and an optional `Z` or numeric offset. Anything
    /// else returns `None` rather than a guess, so a caller can fall back to
    /// showing the raw string.
    #[must_use]
    pub fn parse_rfc3339(value: &str) -> Option<Self> {
        let bytes = value.as_bytes();
        if bytes.len() < 19 {
            return None;
        }
        let year: i32 = value.get(0..4)?.parse().ok()?;
        let month: u32 = value.get(5..7)?.parse().ok()?;
        let day: u32 = value.get(8..10)?.parse().ok()?;
        let hour: u32 = value.get(11..13)?.parse().ok()?;
        let minute: u32 = value.get(14..16)?.parse().ok()?;
        let second: u32 = value.get(17..19)?.parse().ok()?;

        if bytes[4] != b'-' || bytes[7] != b'-' {
            return None;
        }
        if bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ' {
            return None;
        }
        if bytes[13] != b':' || bytes[16] != b':' {
            return None;
        }
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        if hour > 23 || minute > 59 || second > 60 {
            return None;
        }

        let parsed = Self {
            year,
            month,
            day,
            hour,
            minute,
            // A leap second is clamped rather than rejected.
            second: second.min(59),
        };

        // Reject a date that does not exist. `days_from_civil` clamps rather
        // than failing, so 2100-02-29 would otherwise be stored verbatim and
        // reported back as a real date.
        if Self::from_unix(parsed.to_unix()) != parsed {
            return None;
        }

        // Normalise a numeric offset back to UTC so comparisons are sound.
        let offset = value[19..].trim_start_matches(|c: char| c.is_ascii_digit() || c == '.');
        if let Some(sign) = offset.chars().next()
            && (sign == '+' || sign == '-')
        {
            let hours: i64 = offset.get(1..3)?.parse().ok()?;
            let minutes: i64 = offset.get(4..6).unwrap_or("00").parse().unwrap_or(0);
            let shift = hours * 3600 + minutes * 60;
            let seconds = if sign == '+' {
                parsed.to_unix() - shift
            } else {
                parsed.to_unix() + shift
            };
            return Some(Self::from_unix(seconds));
        }

        Some(parsed)
    }

    /// Whole days from `self` to `later`, negative if `later` is earlier.
    #[must_use]
    pub fn days_until(self, later: Self) -> i64 {
        (later.to_unix() - self.to_unix()) / DAY
    }
}

impl fmt::Display for UtcDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

/// Days since the Unix epoch for a civil date.
///
/// Howard Hinnant's `days_from_civil`, with the era shifted so that the epoch
/// is 1970-01-01.
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let month = month.clamp(1, 12);
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day.clamp(1, 31));
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = shifted_month + if shifted_month < 10 { 3 } else { -9 };
    (
        i32::try_from(year + i64::from(month <= 2)).unwrap_or(1970),
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use super::UtcDateTime;

    #[test]
    fn converts_the_epoch() {
        let epoch = UtcDateTime::from_unix(0);
        assert_eq!(epoch.to_rfc3339(), "1970-01-01T00:00:00Z");
        assert_eq!(epoch.to_unix(), 0);
    }

    /// Round-tripping across leap years, century boundaries, and month ends is
    /// what a hand-written calendar has to prove.
    #[test]
    fn round_trips_notable_dates() {
        let cases = [
            "1970-01-01T00:00:00Z",
            "1999-12-31T23:59:59Z",
            "2000-02-29T12:00:00Z",
            "2024-02-29T00:00:00Z",
            "2026-08-27T14:35:02Z",
            "2100-03-01T00:00:00Z",
            "2038-01-19T03:14:07Z",
        ];
        for case in cases {
            let parsed = UtcDateTime::parse_rfc3339(case).expect("parses");
            assert_eq!(parsed.to_rfc3339(), case, "round trip failed for {case}");
            assert_eq!(
                UtcDateTime::from_unix(parsed.to_unix()).to_rfc3339(),
                case,
                "unix round trip failed for {case}"
            );
        }
    }

    /// 2100 is not a leap year, which a naive `year % 4` rule gets wrong. A
    /// date that does not exist must be refused rather than echoed back as if
    /// it did.
    #[test]
    fn handles_the_century_leap_rule() {
        let leap = UtcDateTime::parse_rfc3339("2000-02-29T00:00:00Z").expect("2000 is a leap year");
        assert_eq!(leap.day, 29);
        assert!(UtcDateTime::parse_rfc3339("2100-02-29T00:00:00Z").is_none());
        assert!(UtcDateTime::parse_rfc3339("2026-02-29T00:00:00Z").is_none());
        assert!(UtcDateTime::parse_rfc3339("2026-04-31T00:00:00Z").is_none());
        assert!(UtcDateTime::parse_rfc3339("2026-04-30T00:00:00Z").is_some());
    }

    #[test]
    fn finds_the_billing_period_boundaries() {
        let now = UtcDateTime::parse_rfc3339("2026-08-27T14:35:02Z").expect("parses");
        assert_eq!(now.start_of_month().to_rfc3339(), "2026-08-01T00:00:00Z");
        assert_eq!(
            now.start_of_next_month().to_rfc3339(),
            "2026-09-01T00:00:00Z"
        );
        assert_eq!(now.start_of_day().to_rfc3339(), "2026-08-27T00:00:00Z");
    }

    /// December must roll over into the next year.
    #[test]
    fn december_rolls_into_january() {
        let december = UtcDateTime::parse_rfc3339("2026-12-15T09:00:00Z").expect("parses");
        assert_eq!(
            december.start_of_next_month().to_rfc3339(),
            "2027-01-01T00:00:00Z"
        );
    }

    #[test]
    fn parses_the_fractional_and_offset_forms_oci_emits() {
        let fractional =
            UtcDateTime::parse_rfc3339("2026-02-01T09:15:00.000Z").expect("fractional parses");
        assert_eq!(fractional.to_rfc3339(), "2026-02-01T09:15:00Z");

        let offset =
            UtcDateTime::parse_rfc3339("2026-02-01T09:15:00+02:00").expect("offset parses");
        assert_eq!(
            offset.to_rfc3339(),
            "2026-02-01T07:15:00Z",
            "a positive offset must be subtracted to reach UTC"
        );

        let behind = UtcDateTime::parse_rfc3339("2026-02-01T09:15:00-05:00").expect("parses");
        assert_eq!(behind.to_rfc3339(), "2026-02-01T14:15:00Z");
    }

    /// Anything unrecognised returns None so the caller can show the raw value
    /// instead of a fabricated date.
    #[test]
    fn refuses_to_guess_at_unparseable_input() {
        for value in [
            "",
            "not a date",
            "2026-13-01T00:00:00Z",
            "2026-02-01",
            "20260201T091500Z",
            "2026-02-01X09:15:00Z",
        ] {
            assert!(
                UtcDateTime::parse_rfc3339(value).is_none(),
                "{value:?} must not parse"
            );
        }
    }

    #[test]
    fn measures_whole_days_between_instants() {
        let start = UtcDateTime::parse_rfc3339("2026-08-01T00:00:00Z").expect("parses");
        let end = UtcDateTime::parse_rfc3339("2026-08-27T00:00:00Z").expect("parses");
        assert_eq!(start.days_until(end), 26);
        assert_eq!(end.days_until(start), -26);
    }

    #[test]
    fn ordering_follows_the_timeline() {
        let earlier = UtcDateTime::parse_rfc3339("2026-01-01T00:00:00Z").expect("parses");
        let later = UtcDateTime::parse_rfc3339("2026-06-01T00:00:00Z").expect("parses");
        assert!(earlier < later);
        let mut dates = [later, earlier];
        dates.sort_unstable();
        assert_eq!(dates[0], earlier);
    }

    #[test]
    fn now_is_after_the_epoch() {
        assert!(UtcDateTime::now().year >= 2024);
    }
}
