//! The signed offset between this host's clock and the login server's.

use std::time::SystemTime;

/// How far the login server's clock is ahead of this host's, in seconds.
///
/// A signed offset, not a step window. A verifier accepts a range of counters and so is described by
/// a step count; this crate is not a verifier. It has to produce the one code the server expects, so
/// "the clock is seven seconds fast" is the case that has to be representable, and a step count
/// cannot hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClockSkew(i64);

impl ClockSkew {
    /// No correction. What a caller passes until server time is in hand.
    pub const NONE: Self = Self(0);

    /// Past this many seconds in either direction, a caller should tell the user their clock is
    /// wrong. The threshold is data here; the sentence belongs to whatever presents it.
    pub const ADVISORY_SECONDS: i64 = 10;

    /// A correction of `seconds`, positive when the server is ahead.
    #[must_use]
    pub const fn from_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// The offset between two readings of the same moment.
    ///
    /// Saturating: an absurd pair of instants clamps rather than wrapping, so a machine whose clock
    /// reads a thousand years out produces a large offset instead of a small one with the sign
    /// flipped.
    #[must_use]
    pub fn between(server: SystemTime, local: SystemTime) -> Self {
        match server.duration_since(local) {
            Ok(ahead) => Self(i64::try_from(ahead.as_secs()).unwrap_or(i64::MAX)),
            Err(behind) => Self(
                i64::try_from(behind.duration().as_secs())
                    .map_or(i64::MIN, |seconds| seconds.saturating_neg()),
            ),
        }
    }

    /// The correction, in seconds.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.0
    }

    /// Whether the offset is far enough out to be worth telling the user about.
    #[must_use]
    pub const fn is_advisory(self) -> bool {
        self.0 > Self::ADVISORY_SECONDS || self.0 < -Self::ADVISORY_SECONDS
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn an_offset_carries_its_sign() {
        let local = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let ahead = local + Duration::from_secs(7);
        let behind = local - Duration::from_secs(7);
        assert_eq!(ClockSkew::between(ahead, local).seconds(), 7);
        assert_eq!(ClockSkew::between(behind, local).seconds(), -7);
        assert_eq!(ClockSkew::between(local, local), ClockSkew::NONE);
    }

    /// The advisory threshold is inclusive of the boundary on purpose: ten seconds is the largest
    /// drift that is not worth a sentence, so a caller that renders on `is_advisory` does not start
    /// nagging at exactly the recommended tolerance.
    #[test]
    fn the_advisory_threshold_is_symmetric_and_inclusive() {
        assert!(!ClockSkew::from_seconds(10).is_advisory());
        assert!(!ClockSkew::from_seconds(-10).is_advisory());
        assert!(ClockSkew::from_seconds(11).is_advisory());
        assert!(ClockSkew::from_seconds(-11).is_advisory());
        assert!(!ClockSkew::NONE.is_advisory());
    }

    /// A clock a century out is still a reading, and the correction it produces has to keep its
    /// sign and its magnitude rather than wrapping into something that looks reasonable.
    #[test]
    fn a_large_offset_keeps_its_sign() {
        const CENTURY: u64 = 100 * 365 * 24 * 60 * 60;
        let local = SystemTime::UNIX_EPOCH + Duration::from_secs(CENTURY);
        let far = local + Duration::from_secs(CENTURY);
        let ahead = ClockSkew::between(far, local).seconds();
        let behind = ClockSkew::between(local, far).seconds();
        assert_eq!(ahead, i64::try_from(CENTURY).unwrap_or(i64::MAX));
        assert_eq!(behind, -ahead);
    }
}
