//! Host identity and time for the login flow.
//!
//! The protocol crates read no clock and no environment of their own: each exports a pure
//! constructor over facts a caller supplies, and this module is where those facts are gathered, so
//! the composition root is the only place that touches the host. [`computer_id`] folds the install's
//! stored identifier into `sqex-proto`'s `ComputerId::from_facts`. [`launcher_time_now`] decomposes
//! the UTC wall clock into a `LauncherTime::from_parts`. [`game_tick`] reads the monotonic tick the
//! game re-derives its launch-argument key from, as `sqex-crypto`'s `TickCount`. [`Clock`] is the
//! injectable now-in-seconds source the session cache measures its validity window against, so the
//! window is deterministically testable.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sqex_crypto::TickCount;
use sqex_proto::{ComputerId, LauncherTime};
use uuid::Uuid;

use crate::error::CoreError;
use crate::store::Store;

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

/// The machine identifier every frontier and OAuth request carries, folded from this install's own
/// stored id rather than from anything about the host.
///
/// The reference launcher hashes the machine and user names, which pins a persistent, unrotatable
/// identifier to a string that is frequently a real person's name. A live login established that the
/// server does not validate this value at all, so nothing on the wire asks for that linkage. What
/// the wire does expect is a value that holds still, since one that changed per request would be a
/// signal of its own; a single random id minted per install and kept satisfies both halves.
///
/// A store that cannot be read or written falls back to a value good for this run alone, which costs
/// stability rather than privacy.
#[must_use]
pub fn computer_id(store: &Store) -> ComputerId {
    let install = store.install_id().unwrap_or_else(|err| {
        tracing::warn!(%err, "no install id could be stored; using a value for this run only");
        Uuid::new_v4()
    });
    // The install id is the whole input. The remaining facts are fixed rather than read from the
    // host, so there is no channel for one to reach the digest.
    ComputerId::from_facts(&install.to_string(), "", "", 0)
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

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn store() -> (TempDir, Store) {
        let dir = TempDir::new().unwrap();
        let store = Store::new(dir.path().to_path_buf());
        (dir, store)
    }

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

    /// Minted on the first read and kept: a second run over the same store reads the id the first
    /// one wrote, so what the server sees holds still.
    #[test]
    fn computer_id_is_stable_across_runs() {
        let (dir, first_run) = store();
        let second_run = Store::new(dir.path().to_path_buf());
        assert_eq!(computer_id(&first_run), computer_id(&second_run));
    }

    /// Nothing about the machine is folded in, so two installs share nothing, whether they sit on
    /// one host or two. This is the property the whole derivation exists for.
    #[test]
    fn computer_id_differs_between_installs() {
        let (_one, one) = store();
        let (_two, two) = store();
        assert_ne!(computer_id(&one), computer_id(&two));
    }

    /// The shape the launcher user agent embeds: five bytes rendered as ten lowercase hex
    /// characters, whose sum is zero because the leading byte is the checksum of the other four.
    #[test]
    fn computer_id_keeps_the_wire_shape() {
        let (_dir, store) = store();
        let rendered = computer_id(&store).to_string();

        assert_eq!(rendered.len(), 10);
        assert!(
            rendered
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );

        let mut sum = 0u8;
        for pair in 0..5 {
            let byte = u8::from_str_radix(&rendered[pair * 2..pair * 2 + 2], 16).unwrap();
            sum = sum.wrapping_add(byte);
        }
        assert_eq!(sum, 0);
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
