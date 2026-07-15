//! The launcher's notion of "now", injected rather than read from an ambient clock.
//!
//! SE stamps version checks and frontier requests with UTC timestamps that double as CDN cache keys.
//! Keeping the clock out of this crate makes the formatting deterministic and golden-testable: a caller
//! supplies the broken-down UTC fields and a Unix-millisecond value, and the live reader is a seam
//! filled in by the composition root.

/// A UTC instant the launcher stamps onto requests.
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
    /// Construct from fixed parts. Deterministic; the entry point for tests and goldens.
    #[must_use]
    pub fn from_parts(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        unix_millis: u64,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            unix_millis,
        }
    }

    /// Read the host clock. Filled in by the composition root.
    #[must_use]
    pub fn now() -> Self {
        todo!("read the host UTC clock")
    }

    /// The boot-version check timestamp `yyyy-MM-dd-HH-mm` with the minute floored to the ten: SE
    /// overwrites the minute's ones-digit with `0` to coarsen the CDN cache key.
    #[must_use]
    pub fn boot_check_timestamp(&self) -> String {
        let floored = self.minute - self.minute % 10;
        format!(
            "{:04}-{:02}-{:02}-{:02}-{:02}",
            self.year, self.month, self.day, self.hour, floored
        )
    }

    /// The full-minute timestamp `yyyy-MM-dd-HH-mm` used in the frontier referer.
    #[must_use]
    pub fn referer_timestamp(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}-{:02}-{:02}",
            self.year, self.month, self.day, self.hour, self.minute
        )
    }

    /// The Unix-millisecond cache-buster sent as `_=` on frontier requests.
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
    fn cache_buster_is_the_millis() {
        let t = LauncherTime::from_parts(2024, 1, 2, 3, 7, 1_704_164_820_000);
        assert_eq!(t.cache_buster(), 1_704_164_820_000);
    }
}
