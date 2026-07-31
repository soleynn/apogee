//! Host identity and time for the login flow.
//!
//! The composition root owns identity and the clock: `sqex-proto`'s own `ComputerId::from_host` and
//! `LauncherTime::now`, and `sqex-crypto`'s `TickCount`, defer here by design. [`computer_id`] builds
//! the launcher's machine fingerprint from best-effort host facts (not server-validated, so a
//! stable-per-host value is enough). [`launcher_time_now`] stamps requests with the current UTC wall
//! clock. [`game_tick`] reads the monotonic tick the game re-derives its launch-argument key from.
//! [`Clock`] is the injectable now-in-seconds source the session cache measures its validity window
//! against, so the window is deterministically testable.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sqex_crypto::TickCount;
use sqex_proto::{ComputerId, LauncherTime};

use crate::error::CoreError;

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

/// The monotonic tick the game will re-derive its launch-argument key from.
///
/// The game runs under Wine, which maps `GetTickCount` onto the host `CLOCK_MONOTONIC_RAW`, so the
/// launcher reads that same clock. Mirrors the reference launcher's Linux tick source: read
/// `CLOCK_MONOTONIC_RAW`, then `tv_sec * 1000 + tv_nsec / 1_000_000` truncated to 32 bits.
///
/// Read this as late as possible. The game masks the tick to its high 16 bits and retries exactly one
/// 65536 ms step down, so a reading more than two of those steps old cannot be recovered and the
/// launch fails with nothing to see.
///
/// # Errors
///
/// [`CoreError::NoTickSource`] where the host exposes no such clock, which is every non-Linux target:
/// there the game is not a Wine process and this mapping does not hold.
#[cfg(target_os = "linux")]
pub fn game_tick() -> Result<TickCount, CoreError> {
    use rustix::time::{ClockId, clock_gettime};
    let ts = clock_gettime(ClockId::MonotonicRaw);
    Ok(TickCount::from_raw(timespec_to_tick(ts.tv_sec, ts.tv_nsec)))
}

/// Off Linux the game is not a Wine process, so no host clock is known to match what it reads.
#[cfg(not(target_os = "linux"))]
pub fn game_tick() -> Result<TickCount, CoreError> {
    Err(CoreError::NoTickSource)
}

/// The pure fold from a `CLOCK_MONOTONIC_RAW` timespec to the launcher's 32-bit tick.
///
/// Wrapping 64-bit arithmetic then a 32-bit truncation, reproducing the reference launcher's
/// unchecked `long` math and `(uint)` cast for every input.
#[cfg(target_os = "linux")]
fn timespec_to_tick(sec: i64, nsec: i64) -> u32 {
    sec.wrapping_mul(1000).wrapping_add(nsec / 1_000_000) as u32
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

    #[cfg(target_os = "linux")]
    #[test]
    fn tick_fold_matches_the_reference() {
        assert_eq!(timespec_to_tick(0, 0), 0);
        assert_eq!(timespec_to_tick(1, 0), 1000);
        assert_eq!(timespec_to_tick(0, 1_000_000), 1);
        assert_eq!(timespec_to_tick(0, 999_999), 0); // sub-ms truncated
        assert_eq!(timespec_to_tick(4_294_967, 301_000_000), 5); // 32-bit wrap
    }

    /// The clock this host actually exposes. `TickCount` deliberately has no accessor, so what is
    /// checkable from here is that the read succeeds; the fold above is where the logic lives.
    #[cfg(target_os = "linux")]
    #[test]
    fn game_tick_reads_the_host_clock() {
        assert!(game_tick().is_ok());
    }
}
