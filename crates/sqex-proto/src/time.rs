// The launcher's notion of "now", injected rather than read from an ambient clock. SE stamps version
// checks and frontier requests with UTC timestamps that double as CDN cache keys. Keeping the clock
// out of this crate makes the formatting deterministic and golden-testable: a caller supplies the
// broken-down UTC fields and a Unix-millisecond value, and the live reader is a seam filled in by the
// composition root.
#[derive(Debug, Clone, Copy)]
pub struct LauncherTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    unix_millis: u64,
}

impl LauncherTime {
    #[must_use]
    pub fn from_parts(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        unix_millis: u64,
    ) -> Self {
        debug_assert!(
            year <= 9999
                && (1..=12).contains(&month)
                && (1..=31).contains(&day)
                && hour <= 23
                && minute <= 59,
            "LauncherTime fields are out of range for the fixed-width yyyy-MM-dd-HH-mm timestamp"
        );
        Self {
            year,
            month,
            day,
            hour,
            minute,
            unix_millis,
        }
    }

    // SE overwrites the minute's ones-digit with 0 to coarsen the CDN cache key.
    #[must_use]
    pub fn boot_check_timestamp(&self) -> String {
        let floored = self.minute - self.minute % 10;
        format!(
            "{:04}-{:02}-{:02}-{:02}-{:02}",
            self.year, self.month, self.day, self.hour, floored
        )
    }

    #[must_use]
    pub fn referer_timestamp(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}-{:02}-{:02}",
            self.year, self.month, self.day, self.hour, self.minute
        )
    }

    #[must_use]
    pub fn cache_buster(&self) -> u64 {
        self.unix_millis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_check_floors_the_minute_to_the_ten() {
        let t = LauncherTime::from_parts(2024, 1, 2, 3, 47, 0);
        assert_eq!(t.boot_check_timestamp(), "2024-01-02-03-40");
    }

    #[test]
    fn boot_check_floors_single_digit_minutes_to_zero() {
        let t = LauncherTime::from_parts(2024, 1, 2, 3, 7, 0);
        assert_eq!(t.boot_check_timestamp(), "2024-01-02-03-00");
    }

    #[test]
    fn referer_keeps_the_full_minute_and_zero_pads() {
        let t = LauncherTime::from_parts(2024, 1, 2, 3, 7, 0);
        assert_eq!(t.referer_timestamp(), "2024-01-02-03-07");
    }

    #[test]
    fn from_parts_accepts_the_range_boundaries() {
        let t = LauncherTime::from_parts(9999, 12, 31, 23, 59, 0);
        assert_eq!(t.referer_timestamp(), "9999-12-31-23-59");
        let t = LauncherTime::from_parts(0, 1, 1, 0, 0, 0);
        assert_eq!(t.referer_timestamp(), "0000-01-01-00-00");
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn from_parts_rejects_fields_that_would_widen_the_timestamp() {
        // Unchecked, these render "2024-13-45-255-255": a non-fixed-width timestamp that is no longer the
        // cache key SE's CDN expects. `{:02}` sets a minimum width, not a maximum.
        let _ = LauncherTime::from_parts(2024, 13, 45, 255, 255, 0);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn from_parts_rejects_a_zero_month() {
        // Zero pads to two digits, so it never widens the timestamp; it is still not a real instant, and
        // the range is the type's invariant rather than a formatting rule.
        let _ = LauncherTime::from_parts(2024, 0, 1, 0, 0, 0);
    }

    #[test]
    fn cache_buster_is_the_millis() {
        let t = LauncherTime::from_parts(2024, 1, 2, 3, 7, 1_704_164_820_000);
        assert_eq!(t.cache_buster(), 1_704_164_820_000);
    }
}
