//! Host identity and time for the login flow.
//!
//! The composition root owns identity and the clock: `sqex-proto`'s own `ComputerId::from_host` and
//! `LauncherTime::now` defer here by design. [`computer_id`] builds the launcher's machine
//! fingerprint from best-effort host facts (not server-validated, so a stable-per-host value is
//! enough). [`launcher_time_now`] stamps requests with the current UTC wall clock. [`Clock`] is the
//! injectable now-in-seconds source the session cache measures its validity window against, so the
//! window is deterministically testable.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sqex_proto::{ComputerId, LauncherTime};

/// A source of the current time in whole seconds since the Unix epoch. Injectable so the session
/// cache's validity window can be driven deterministically in tests.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The real wall-clock source, in seconds since the Unix epoch.
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// The launcher's machine fingerprint, from best-effort host facts. The value is not validated by
/// the server (a random-per-install id is accepted), so env-derived facts with plain fallbacks are
/// sufficient, and it is stable for a given host.
#[must_use]
pub fn computer_id() -> ComputerId {
    let machine = env_or("HOSTNAME", "apogee");
    let user = env_or("USER", "apogee");
    let processors = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1) as u32;
    ComputerId::from_facts(&machine, &user, "Linux", processors)
}

/// The current UTC instant as a [`LauncherTime`].
#[must_use]
pub fn launcher_time_now() -> LauncherTime {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    launcher_time_from_epoch(since_epoch.as_secs(), since_epoch.as_millis() as u64)
}

/// Decompose `secs`/`millis` since the epoch into a calendar [`LauncherTime`] (UTC), using Howard
/// Hinnant's public-domain `civil_from_days`, so no calendar crate is pulled in.
fn launcher_time_from_epoch(secs: u64, millis: u64) -> LauncherTime {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let hour = (secs_of_day / 3_600) as u8;
    let minute = ((secs_of_day % 3_600) / 60) as u8;

    // civil_from_days: days since 1970-01-01 -> (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year_civil = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let year = (year_civil + i64::from(month <= 2)) as u16;

    LauncherTime::from_parts(year, month, day, hour, minute, millis)
}

/// The value of environment variable `var`, or `fallback` when it is unset or empty.
fn env_or(var: &str, fallback: &str) -> String {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `referer_timestamp` renders `yyyy-MM-dd-HH-mm`, so it pins every decomposed field.
    #[test]
    fn decomposes_known_epochs() {
        // The Unix epoch.
        assert_eq!(
            launcher_time_from_epoch(0, 0).referer_timestamp(),
            "1970-01-01-00-00"
        );
        // 2024-01-02 03:07:00 UTC.
        assert_eq!(
            launcher_time_from_epoch(1_704_164_820, 1_704_164_820_000).referer_timestamp(),
            "2024-01-02-03-07"
        );
        // A leap day, to exercise the February-29 path.
        assert_eq!(
            launcher_time_from_epoch(951_825_600, 951_825_600_000).referer_timestamp(),
            "2000-02-29-12-00"
        );
        // A year-end instant, to exercise the December path.
        assert_eq!(
            launcher_time_from_epoch(1_640_995_140, 1_640_995_140_000).referer_timestamp(),
            "2021-12-31-23-59"
        );
    }

    #[test]
    fn computer_id_is_stable_for_a_host() {
        assert_eq!(computer_id(), computer_id());
    }
}
