//! Backoff, jitter, and the one place that decides what a failure is worth.
//!
//! Every retry site in the crate asks the same two questions: is this failure the kind that could
//! succeed on a second try, and how long should the transfer wait first. [`classify_status`] answers
//! the first for an HTTP status, [`RetryPolicy::delay`] answers the second, and both engines route
//! through them so a status cannot be retryable on one transfer path and fatal on the other.
//!
//! The delay is exponential with equal jitter: half the computed backoff, plus a random draw over
//! the other half. Equal jitter (rather than a full-range draw) keeps a guaranteed floor under every
//! wait, so a retry storm still spreads out but a client can never re-request immediately. The
//! randomness comes from a small counter-based generator seeded once from the operating system; it
//! decides nothing but wait times, so it is never security-bearing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::header::{HeaderMap, RETRY_AFTER};
use tokio_util::sync::CancellationToken;

/// The odd 64-bit constant SplitMix64 advances its counter by.
const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

/// What a failed attempt is worth: another try, or an immediate failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// A throttling or overload answer: back off and ask the same source again, honoring any
    /// `Retry-After` the response carried.
    Retryable,
    /// A failure that will not become a success: fail the transfer now.
    Fatal,
}

/// Whether a status the transfer cannot use is worth asking again.
///
/// Retryable is the throttle-and-overload set: `408` (the server gave up waiting for the request),
/// `429` (rate limited), and the `500`/`502`/`503`/`504` bad-gateway-and-overload group a CDN emits
/// while a node restarts. Everything else, notably every other `4xx`, describes a request that will
/// be refused identically forever. Statuses a transfer *can* use (`200`, `206`, `416`) never reach
/// here: each engine settles those against its own resume disposition first.
pub(crate) fn classify_status(status: u16) -> Class {
    match status {
        408 | 429 | 500 | 502 | 503 | 504 => Class::Retryable,
        _ => Class::Fatal,
    }
}

/// The pause a `Retry-After` header asked for, in its delta-seconds form only.
///
/// The HTTP-date form yields `None`, and so does anything unparseable, which sends the caller to its
/// computed backoff instead. Parsing dates would mean either a date crate or an in-house parser for
/// three date formats, to gain nothing a bounded exponential backoff does not already provide: a
/// server that wants a longer pause than the ceiling does not get one either way (see
/// [`RetryPolicy::delay`]). Total and allocation-free on hostile bytes: a non-ASCII value fails
/// `to_str`, and the parse is bounded by the header's own length.
pub(crate) fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get(RETRY_AFTER)?.to_str().ok()?;
    raw.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// How a transfer retries: how many attempts one unit of work gets, and how long it waits between
/// them.
///
/// Exponential backoff from [`base_delay`](Self::base_delay), multiplied per attempt, capped at
/// [`max_delay`](Self::max_delay), and jittered. One policy covers every retry site: a segment whose
/// connection dropped or went silent, a block that failed its hash, the range probe, and a
/// single-connection transfer that was cut off mid-body.
///
/// The defaults are 8 attempts, 500 ms doubling to a 30 s ceiling. 500 ms is short enough to be
/// invisible on a transient blip and long enough for a CDN node to finish restarting; doubling to a
/// 30 s ceiling keeps a throttled client polite without letting a server-named pause become an
/// unbounded hang; and eight attempts spends about a minute on one stuck range before reporting a
/// precise failure, so a genuinely dead source fails inside a patch session rather than hanging it.
///
/// # Examples
///
/// ```
/// # use std::time::Duration;
/// # use apogee_fetch::{FetcherBuilder, RetryPolicy};
/// # fn fail_fast(builder: FetcherBuilder) -> FetcherBuilder {
/// builder.retry_policy(
///     RetryPolicy::default()
///         .max_attempts(3)
///         .base_delay(Duration::from_millis(100))
///         .max_delay(Duration::from_secs(1)),
/// )
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
    multiplier: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            multiplier: 2,
        }
    }
}

impl RetryPolicy {
    /// How many times one unit of work is attempted in total, the first try included (default 8).
    /// Clamped to at least 1, so a policy can disable retrying but never disable the work.
    #[must_use]
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts.max(1);
        self
    }

    /// The wait after the first failure (default 500 ms).
    #[must_use]
    pub fn base_delay(mut self, delay: Duration) -> Self {
        self.base_delay = delay;
        self
    }

    /// The ceiling on any wait, including one a server's `Retry-After` asked for (default 30 s).
    #[must_use]
    pub fn max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// What the wait is multiplied by per failed attempt (default 2). Clamped to at least 1.
    #[must_use]
    pub fn multiplier(mut self, multiplier: u32) -> Self {
        self.multiplier = multiplier.max(1);
        self
    }

    /// Whether work that has already failed `attempts` times may be tried again.
    pub(crate) fn may_retry(self, attempts: u32) -> bool {
        attempts < self.max_attempts
    }

    /// How long to wait after `attempts` failures, honoring a server-named `retry_after` but never
    /// trusting it.
    ///
    /// The computed backoff is `base * multiplier^(attempts - 1)`, capped at the ceiling and then
    /// jittered into the top half of that interval. A `Retry-After` is clamped to the same ceiling
    /// before it is applied, because it is server-controlled input and an unclamped one is a hang
    /// the server gets to choose; whichever of the two is longer wins, so the transfer is never less
    /// polite than the server asked and never parks for longer than the policy allows.
    pub(crate) fn delay(
        self,
        attempts: u32,
        retry_after: Option<Duration>,
        jitter: &Jitter,
    ) -> Duration {
        let jittered = self.jittered_backoff(attempts, jitter);
        match retry_after {
            Some(asked) => jittered.max(asked.min(self.max_delay)),
            None => jittered,
        }
    }

    /// The computed backoff for `attempts` failures, spread over the top half of the interval.
    fn jittered_backoff(self, attempts: u32, jitter: &Jitter) -> Duration {
        let half = self.exponential(attempts) / 2;
        let spread = u64::try_from(half.as_nanos()).unwrap_or(u64::MAX);
        half + Duration::from_nanos(jitter.below(spread))
    }

    /// The un-jittered exponential term, saturating at the ceiling rather than overflowing.
    fn exponential(self, attempts: u32) -> Duration {
        let factor = self
            .multiplier
            .checked_pow(attempts.saturating_sub(1))
            .unwrap_or(u32::MAX);
        self.base_delay.saturating_mul(factor).min(self.max_delay)
    }
}

/// The jitter source: a counter-based generator seeded once from the operating system.
///
/// SplitMix64 over an atomically advancing counter, so the segment workers of one transfer draw
/// concurrently without a lock and without sharing a value. One per [`Fetcher`](crate::Fetcher).
#[derive(Debug)]
pub(crate) struct Jitter {
    counter: AtomicU64,
}

impl Default for Jitter {
    fn default() -> Self {
        Self::new()
    }
}

impl Jitter {
    /// Seed from the system generator, falling back to the wall clock if it is unavailable. Nothing
    /// here is security-bearing, so a weak fallback is a worse spread, never a weak secret.
    pub(crate) fn new() -> Self {
        let seed = getrandom::u64().unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(GOLDEN_GAMMA, |since| {
                    u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
                })
        });
        Self {
            counter: AtomicU64::new(seed),
        }
    }

    /// A uniform-enough draw in `[0, n)`, or `0` when `n` is `0`.
    pub(crate) fn below(&self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let mut z = self
            .counter
            .fetch_add(GOLDEN_GAMMA, Ordering::Relaxed)
            .wrapping_add(GOLDEN_GAMMA);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) % n
    }
}

/// Wait out a backoff, returning `false` if `cancel` fired first (the caller must then stop rather
/// than retry).
pub(crate) async fn sleep_or_cancel(delay: Duration, cancel: &CancellationToken) -> bool {
    if cancel.is_cancelled() {
        return false;
    }
    if delay.is_zero() {
        return true;
    }
    tokio::select! {
        biased;
        () = cancel.cancelled() => false,
        () = tokio::time::sleep(delay) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        if let Ok(value) = reqwest::header::HeaderValue::from_str(value) {
            map.insert(RETRY_AFTER, value);
        }
        map
    }

    /// The throttle-and-overload set retries; every other status, including the 4xx family that will
    /// be refused identically forever, is fatal.
    #[test]
    fn only_throttle_and_overload_statuses_are_retryable() {
        for status in [408, 429, 500, 502, 503, 504] {
            assert_eq!(classify_status(status), Class::Retryable, "{status}");
        }
        for status in [400, 401, 403, 404, 410, 416, 431, 451, 501, 505] {
            assert_eq!(classify_status(status), Class::Fatal, "{status}");
        }
    }

    /// Only the delta-seconds form of `Retry-After` is read; a date or garbage falls back to the
    /// computed backoff rather than to a guess.
    #[test]
    fn retry_after_reads_delta_seconds_only() {
        assert_eq!(retry_after(&headers("120")), Some(Duration::from_secs(120)));
        assert_eq!(retry_after(&headers(" 7 ")), Some(Duration::from_secs(7)));
        assert_eq!(retry_after(&headers("0")), Some(Duration::ZERO));
        assert_eq!(retry_after(&headers("Wed, 21 Oct 2026 07:28:00 GMT")), None);
        assert_eq!(retry_after(&headers("-5")), None);
        assert_eq!(retry_after(&headers("12.5")), None);
        assert_eq!(retry_after(&headers("")), None);
        assert_eq!(retry_after(&headers("99999999999999999999999999")), None);
        assert_eq!(retry_after(&HeaderMap::new()), None);
    }

    /// A `Retry-After` far past the ceiling is clamped to it, so a hostile or buggy server cannot
    /// park a transfer for an hour.
    #[test]
    fn a_retry_after_past_the_ceiling_is_clamped_to_it() {
        let policy = RetryPolicy::default()
            .base_delay(Duration::from_millis(10))
            .max_delay(Duration::from_secs(2));
        let jitter = Jitter::new();
        let asked = Duration::from_secs(3600);
        for attempts in 1..=8 {
            let delay = policy.delay(attempts, Some(asked), &jitter);
            assert!(
                delay <= Duration::from_secs(2),
                "attempt {attempts} waited {delay:?}, past the ceiling",
            );
        }
    }

    /// A `Retry-After` inside the ceiling is honored when it is longer than the computed backoff,
    /// and ignored when the backoff is already longer (later is always allowed, sooner is not).
    #[test]
    fn a_retry_after_inside_the_ceiling_only_ever_lengthens_the_wait() {
        let policy = RetryPolicy::default()
            .base_delay(Duration::from_millis(10))
            .max_delay(Duration::from_secs(60));
        let jitter = Jitter::new();
        let asked = Duration::from_secs(5);
        assert!(policy.delay(1, Some(asked), &jitter) >= asked);
        // A zero-second `Retry-After` cannot shorten the backoff below its own floor.
        assert!(policy.delay(1, Some(Duration::ZERO), &jitter) >= Duration::from_millis(5));
    }

    /// The wait grows per attempt, never below half the computed term and never past the ceiling.
    #[test]
    fn backoff_grows_within_its_floor_and_ceiling() {
        let policy = RetryPolicy::default()
            .base_delay(Duration::from_millis(100))
            .max_delay(Duration::from_secs(4));
        let jitter = Jitter::new();
        for (attempts, floor, ceiling) in [
            (1u32, Duration::from_millis(50), Duration::from_millis(100)),
            (2, Duration::from_millis(100), Duration::from_millis(200)),
            (3, Duration::from_millis(200), Duration::from_millis(400)),
            (9, Duration::from_secs(2), Duration::from_secs(4)),
            // Far past the point where the multiplier would overflow a u32.
            (400, Duration::from_secs(2), Duration::from_secs(4)),
        ] {
            let delay = policy.delay(attempts, None, &jitter);
            assert!(
                delay >= floor && delay <= ceiling,
                "attempt {attempts} waited {delay:?}, outside {floor:?}..={ceiling:?}",
            );
        }
    }

    /// Jitter actually varies the wait, so a fleet of clients retrying together spreads out instead
    /// of arriving in lockstep.
    #[test]
    fn jitter_spreads_repeated_draws() {
        let policy = RetryPolicy::default().base_delay(Duration::from_secs(1));
        let jitter = Jitter::new();
        let mut seen: Vec<Duration> = (0..32).map(|_| policy.delay(3, None, &jitter)).collect();
        seen.sort_unstable();
        seen.dedup();
        assert!(seen.len() > 16, "only {} distinct delays", seen.len());
    }

    /// A degenerate policy still terminates: a zero multiplier is clamped to 1 and a zero attempt
    /// budget to a single attempt, so neither can produce an endless retry loop.
    #[test]
    fn a_degenerate_policy_still_terminates() {
        let policy = RetryPolicy::default().multiplier(0).max_attempts(0);
        assert!(!policy.may_retry(1));
        let jitter = Jitter::new();
        assert!(policy.delay(5, None, &jitter) <= Duration::from_millis(500));
    }

    /// A cancelled token skips the wait entirely rather than sleeping out a backoff nobody is
    /// waiting for.
    #[tokio::test(start_paused = true)]
    async fn a_cancelled_backoff_does_not_wait() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let started = tokio::time::Instant::now();
        assert!(!sleep_or_cancel(Duration::from_secs(3600), &cancel).await);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// The backoff really elapses: under virtual time the full delay passes before the caller is
    /// allowed to retry.
    #[tokio::test(start_paused = true)]
    async fn a_backoff_elapses_in_full() {
        let cancel = CancellationToken::new();
        let started = tokio::time::Instant::now();
        assert!(sleep_or_cancel(Duration::from_secs(30), &cancel).await);
        assert!(started.elapsed() >= Duration::from_secs(30));
    }
}
