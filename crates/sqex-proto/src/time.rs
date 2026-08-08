//! The launcher's notion of "now", injected rather than read from an ambient clock.
//!
//! SE stamps version checks and frontier requests with UTC timestamps that double as CDN cache
//! keys. Keeping the clock out of this crate makes the formatting deterministic and
//! golden-testable: a caller supplies the broken-down UTC fields and a Unix-millisecond value
//! through [`LauncherTime::from_parts`], and the live clock reader is a seam filled in by the
//! composition root rather than something this crate reads for itself.

/// A UTC instant the launcher stamps onto requests, rendered on demand into the fixed-width formats
/// each endpoint expects.
///
/// # Examples
///
/// ```
/// use sqex_proto::LauncherTime;
///
/// let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 1_704_167_220_000);
/// assert_eq!(now.referer_timestamp(), "2024-01-02-03-47");
/// ```
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
    /// Construct an instant from its broken-down UTC fields and a Unix-millisecond value.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if the fields do not name a real UTC instant: `year` must be `<=
    /// 9999`, `month` in `1..=12`, `day` in `1..=31`, `hour` `<= 23`, and `minute` `<= 59`. This is
    /// the type's invariant rather than mere advice: the renderers below zero-pad each field to a
    /// minimum width, not a maximum, so an out-of-range field would silently widen the fixed-width
    /// `yyyy-MM-dd-HH-mm` timestamp SE keys its CDN cache on. Callers are expected to derive these
    /// fields by decomposing a Unix timestamp, which cannot go out of range, so this is a
    /// `debug_assert` rather than a `Result`: it fires in every test, fuzz, and development build,
    /// but costs nothing in the three call sites that provably cannot fail. In a release build the
    /// check does not run, and an out-of-range field renders a wider (and wrong) timestamp instead
    /// of panicking.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_proto::LauncherTime;
    ///
    /// let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 0);
    /// ```
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

    /// The boot-version check timestamp, `yyyy-MM-dd-HH-mm` with the minute floored to the ten: SE
    /// overwrites the minute's ones-digit with `0` to coarsen the CDN cache key.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_proto::LauncherTime;
    ///
    /// let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 0);
    /// assert_eq!(now.boot_check_timestamp(), "2024-01-02-03-40");
    /// ```
    #[must_use]
    pub fn boot_check_timestamp(&self) -> String {
        let floored = self.minute - self.minute % 10;
        format!(
            "{:04}-{:02}-{:02}-{:02}-{:02}",
            self.year, self.month, self.day, self.hour, floored
        )
    }

    /// The full-minute timestamp `yyyy-MM-dd-HH-mm`, used in the frontier referer. Unlike
    /// [`LauncherTime::boot_check_timestamp`], the minute is not floored.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_proto::LauncherTime;
    ///
    /// let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 0);
    /// assert_eq!(now.referer_timestamp(), "2024-01-02-03-47");
    /// ```
    #[must_use]
    pub fn referer_timestamp(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}-{:02}-{:02}",
            self.year, self.month, self.day, self.hour, self.minute
        )
    }

    /// The Unix-millisecond cache-buster sent as `_=` on frontier requests.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_proto::LauncherTime;
    ///
    /// let now = LauncherTime::from_parts(2024, 1, 2, 3, 47, 1_704_167_220_000);
    /// assert_eq!(now.cache_buster(), 1_704_167_220_000);
    /// ```
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
