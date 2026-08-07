//! Counter arithmetic: an instant to a counter, a counter back to the first second of its window.
//!
//! The step interval is half-open. `[period * k, period * (k + 1))` maps to counter `k`, so an
//! instant exactly on a boundary belongs to the new window and not the old one. Every conversion
//! here is checked rather than truncating: an instant before the epoch, or one pushed there by a
//! skew offset, is a condition a caller is told about instead of a counter that silently wrapped.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{ClockSkew, OtpError};

/// Seconds since the epoch for `at`, shifted by `skew`.
///
/// # Errors
/// [`OtpError::Clock`] if `at` is before the epoch, past what a signed second count holds, or
/// pushed outside that range by `skew`.
pub(crate) fn shifted_seconds(at: SystemTime, skew: ClockSkew) -> Result<i64, OtpError> {
    let unix = at.duration_since(UNIX_EPOCH).map_err(|_| OtpError::Clock)?;
    let seconds = i64::try_from(unix.as_secs()).map_err(|_| OtpError::Clock)?;
    seconds.checked_add(skew.seconds()).ok_or(OtpError::Clock)
}

/// The counter the instant `seconds` falls in.
///
/// # Errors
/// [`OtpError::Clock`] if `seconds` is negative, which is an instant no counter is defined for.
pub(crate) fn counter(seconds: i64, period: u32) -> Result<u64, OtpError> {
    let seconds = u64::try_from(seconds).map_err(|_| OtpError::Clock)?;
    Ok(seconds / u64::from(period))
}

/// The first second of `counter`'s window.
///
/// # Errors
/// [`OtpError::Clock`] if the product is past what a second count holds.
pub(crate) fn window_start(counter: u64, period: u32) -> Result<u64, OtpError> {
    counter
        .checked_mul(u64::from(period))
        .ok_or(OtpError::Clock)
}

/// How much of the window holding `seconds` is left.
///
/// Ranges over `1..=period` and is never zero: at a boundary the whole of the new window remains.
///
/// # Errors
/// [`OtpError::Clock`] if `seconds` is negative.
pub(crate) fn remaining(seconds: i64, period: u32) -> Result<u64, OtpError> {
    let seconds = u64::try_from(seconds).map_err(|_| OtpError::Clock)?;
    let period = u64::from(period);
    Ok(period - (seconds % period))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const PERIOD: u32 = 30;

    /// `Option` rather than `Result`, so an assertion can compare two of them: the error type
    /// carries no equality, deliberately, and every case here is either a counter or the one
    /// out-of-range condition.
    fn at(seconds: i64) -> Option<u64> {
        counter(seconds, PERIOD).ok()
    }

    /// The half-open interval, spelled out at the one boundary every naive implementation gets
    /// wrong: the instant on the boundary belongs to the window that is starting.
    #[test]
    fn the_step_interval_is_half_open() {
        assert_eq!(at(0), Some(0));
        assert_eq!(at(29), Some(0));
        assert_eq!(at(30), Some(1));
        assert_eq!(at(31), Some(1));
        assert_eq!(at(59), Some(1));
        assert_eq!(at(60), Some(2));
    }

    /// An instant before the epoch is refused rather than wrapped into an enormous counter, which is
    /// what an unchecked cast would produce and what would then generate a code nothing accepts.
    #[test]
    fn a_clock_before_the_epoch_is_refused() {
        assert!(matches!(counter(-1, PERIOD), Err(OtpError::Clock)));
        assert!(matches!(remaining(-1, PERIOD), Err(OtpError::Clock)));

        let before = UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert!(matches!(
            shifted_seconds(before, ClockSkew::NONE),
            Err(OtpError::Clock)
        ));
    }

    /// A window whose first second is past what a second count holds is refused rather than wrapped
    /// back into a reachable one. The counter comes out of the reuse guard's walk forward, so it is
    /// arithmetic on a number this crate produced rather than one a caller passed in.
    #[test]
    fn a_window_past_the_end_of_time_is_refused() {
        assert_eq!(
            window_start(u64::MAX / u64::from(PERIOD), PERIOD).ok(),
            Some(u64::MAX / u64::from(PERIOD) * u64::from(PERIOD))
        );
        assert!(matches!(
            window_start(u64::MAX, PERIOD),
            Err(OtpError::Clock)
        ));
        assert!(matches!(
            shifted_seconds(
                UNIX_EPOCH + std::time::Duration::from_secs(1),
                ClockSkew::from_seconds(i64::MAX)
            ),
            Err(OtpError::Clock)
        ));
    }

    /// A skew offset can push an instant just after the epoch to just before it. That is the same
    /// condition as a clock set before the epoch and has to answer the same way.
    #[test]
    fn a_skew_that_reaches_back_past_the_epoch_is_refused() {
        let just_after = UNIX_EPOCH + std::time::Duration::from_secs(5);
        assert_eq!(
            shifted_seconds(just_after, ClockSkew::from_seconds(-10)).ok(),
            Some(-5)
        );
        assert!(matches!(counter(-5, PERIOD), Err(OtpError::Clock)));
    }

    proptest! {
        /// The counter, not the code, is what a boundary moves. Asserting on counters is deliberate:
        /// two adjacent six-digit codes collide once in a million, so an assertion that they differ
        /// is a shrink away from a false failure.
        #[test]
        fn a_boundary_moves_the_counter_by_exactly_one(k in 0i64..100_000_000) {
            let start = k * i64::from(PERIOD);
            prop_assert_eq!(at(start), at(start + 29));
            prop_assert_eq!(at(start + i64::from(PERIOD)), at(start).map(|c| c + 1));
        }

        /// A counter round-trips through the first second of its own window, which is the instant
        /// this crate signs for when it generates a code for a window other than the current one.
        #[test]
        fn a_window_start_maps_back_to_its_counter(seconds in 0i64..i64::from(i32::MAX)) {
            let here = at(seconds);
            let start = here.and_then(|c| window_start(c, PERIOD).ok());
            prop_assert!(start <= u64::try_from(seconds).ok());
            prop_assert_eq!(
                start.and_then(|s| i64::try_from(s).ok()).and_then(at),
                here
            );
        }

        /// The time left in a window is never zero and never more than the period, and it always
        /// lands the clock on a boundary. A test asserting that it hits zero at a boundary is wrong.
        #[test]
        fn time_left_is_never_zero(seconds in 0i64..i64::from(i32::MAX)) {
            let left = remaining(seconds, PERIOD).ok();
            prop_assert!(left.is_some_and(|l| (1..=u64::from(PERIOD)).contains(&l)));
            let boundary = left.map(|l| u64::try_from(seconds).unwrap_or(0) + l);
            prop_assert_eq!(boundary.map(|b| b % u64::from(PERIOD)), Some(0));
        }

        /// The boundary rule is the period's, not thirty seconds'. A period comes out of a stored
        /// secret and reaches every one of these conversions, so a constant hidden in any of them
        /// would put a code for the wrong window on the wire for every profile but the usual one.
        #[test]
        fn every_period_has_the_same_boundary_rule(period in 1u32..=300, k in 0i64..1_000_000) {
            let span = i64::from(period);
            let start = k * span;
            let here = u64::try_from(k).ok();

            prop_assert_eq!(counter(start, period).ok(), here);
            prop_assert_eq!(counter(start + span - 1, period).ok(), here);
            prop_assert_eq!(counter(start + span, period).ok(), here.map(|c| c + 1));

            prop_assert_eq!(remaining(start, period).ok(), Some(u64::from(period)));
            prop_assert_eq!(remaining(start + span - 1, period).ok(), Some(1));

            prop_assert_eq!(
                here.and_then(|c| window_start(c, period).ok()),
                u64::try_from(start).ok()
            );
        }

        /// An offset that stays inside the window leaves the counter where it was; the two that
        /// step out of it move it by exactly one. This is the property the whole skew parameter
        /// exists for, and it is asserted on counters for the same reason as the boundary test.
        #[test]
        fn an_offset_inside_the_window_changes_nothing(
            k in 1i64..100_000_000,
            offset in -15i64..15,
        ) {
            let middle = k * i64::from(PERIOD) + 15;
            let here = at(middle);
            prop_assert_eq!(at(middle + offset), here);
            prop_assert_eq!(at(middle + 15), here.map(|c| c + 1));
            prop_assert_eq!(at(middle - 16), here.map(|c| c - 1));
        }
    }
}
