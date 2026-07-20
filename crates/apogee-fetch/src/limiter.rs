//! A shared, live-adjustable token-bucket speed limiter.
//!
//! One [`LimitHandle`] is cloned to every connection of every job, so they all draw from a single
//! budget counted on payload bytes read off the socket. [`set`](LimitHandle::set) retargets the cap
//! mid-transfer (or lifts it with `None`), matching the reference launcher's live speed control. The
//! bucket runs on `tokio::time`, so a paused-time test drives it deterministically.

use std::sync::{Arc, Mutex};

use tokio::time::{Duration, Instant};

/// A live-adjustable, shared speed limit. Cloning shares the underlying bucket.
#[derive(Clone, Debug)]
pub struct LimitHandle {
    bucket: Arc<Mutex<Bucket>>,
}

#[derive(Debug)]
struct Bucket {
    /// The cap in bytes per second, or `None` for uncapped. A rate of `0` is treated as uncapped.
    rate: Option<u64>,
    /// Available tokens (bytes), kept fractional to avoid rounding drift.
    tokens: f64,
    /// The burst ceiling tokens accrue to after an idle gap; bounds post-idle catch-up.
    capacity: f64,
    /// When `tokens` was last refilled; `None` until the first draw so no `Instant` is minted outside
    /// the runtime.
    last: Option<Instant>,
}

impl LimitHandle {
    /// An uncapped handle: [`acquire`](Self::acquire) never waits until a limit is [`set`](Self::set).
    #[must_use]
    pub fn uncapped() -> Self {
        Self::from_rate(None)
    }

    /// A handle capped at `bytes_per_second`.
    #[must_use]
    pub fn with_limit(bytes_per_second: u64) -> Self {
        Self::from_rate(Some(bytes_per_second))
    }

    fn from_rate(rate: Option<u64>) -> Self {
        Self {
            bucket: Arc::new(Mutex::new(Bucket {
                rate,
                // Start empty so there is no free initial burst: elapsed tracks total/rate tightly.
                tokens: 0.0,
                capacity: burst_capacity(rate),
                last: None,
            })),
        }
    }

    /// Retarget the limit live. `None` lifts it; a new rate re-scales the burst ceiling and clamps any
    /// accumulated tokens to it.
    pub fn set(&self, bytes_per_second: Option<u64>) {
        let mut b = self.lock();
        b.rate = bytes_per_second;
        b.capacity = burst_capacity(bytes_per_second);
        if b.tokens > b.capacity {
            b.tokens = b.capacity;
        }
    }

    /// Wait until `n` bytes' worth of tokens are available, then consume them. Returns immediately when
    /// uncapped. A request larger than the burst ceiling is still served (the ceiling stretches to it
    /// for that draw), so a large chunk cannot deadlock.
    pub(crate) async fn acquire(&self, n: u64) {
        if n == 0 {
            return;
        }
        loop {
            let wait = {
                let mut b = self.lock();
                let Some(rate) = b.rate.filter(|&r| r > 0) else {
                    return;
                };
                let rate = rate as f64;
                let now = Instant::now();
                let last = b.last.unwrap_or(now);
                let refill = now.saturating_duration_since(last).as_secs_f64() * rate;
                let ceiling = b.capacity.max(n as f64);
                b.tokens = (b.tokens + refill).min(ceiling);
                b.last = Some(now);
                if b.tokens >= n as f64 {
                    b.tokens -= n as f64;
                    return;
                }
                Duration::from_secs_f64((n as f64 - b.tokens) / rate)
            };
            tokio::time::sleep(wait).await;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Bucket> {
        // The bucket mutex is only ever held for the O(1) refill math, never across an await.
        crate::util::lock(&self.bucket)
    }
}

/// One second of the rate as the burst ceiling; uncapped needs none.
fn burst_capacity(rate: Option<u64>) -> f64 {
    rate.unwrap_or(0) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Draw `total` bytes in `chunk`-sized pieces and return the virtual time it took.
    async fn drain(handle: &LimitHandle, total: u64, chunk: u64) -> Duration {
        let start = Instant::now();
        let mut done = 0;
        while done < total {
            let n = chunk.min(total - done);
            handle.acquire(n).await;
            done += n;
        }
        Instant::now().saturating_duration_since(start)
    }

    #[tokio::test(start_paused = true)]
    async fn holds_the_rate_within_five_percent() {
        let rate = 1_000_000; // 1 MB/s
        let total = 10_000_000; // 10 seconds' worth
        let handle = LimitHandle::with_limit(rate);
        let elapsed = drain(&handle, total, 64 * 1024).await.as_secs_f64();
        let ideal = total as f64 / rate as f64; // 10.0 s
        assert!(
            (elapsed - ideal).abs() / ideal <= 0.05,
            "elapsed {elapsed}s vs ideal {ideal}s is outside ±5%",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn uncapped_never_waits() {
        let handle = LimitHandle::uncapped();
        let elapsed = drain(&handle, 100_000_000, 1 << 20).await;
        assert_eq!(elapsed, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn lifting_the_limit_mid_stream_stops_throttling() {
        let handle = LimitHandle::with_limit(1_000_000);
        drain(&handle, 1_000_000, 64 * 1024).await; // ~1s of throttled transfer
        handle.set(None);
        let after = drain(&handle, 100_000_000, 1 << 20).await;
        assert_eq!(after, Duration::ZERO, "an uncapped handle must not wait");
    }

    #[tokio::test(start_paused = true)]
    async fn retargeting_to_a_faster_rate_takes_effect() {
        let handle = LimitHandle::with_limit(1_000_000);
        handle.set(Some(4_000_000)); // 4 MB/s
        let elapsed = drain(&handle, 8_000_000, 64 * 1024).await.as_secs_f64();
        let ideal = 8_000_000.0 / 4_000_000.0; // 2.0 s
        assert!(
            (elapsed - ideal).abs() / ideal <= 0.05,
            "elapsed {elapsed}s vs ideal {ideal}s is outside ±5%",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_chunk_larger_than_the_burst_ceiling_is_still_served() {
        // n (2 MB) exceeds the 1 MB/s one-second ceiling; the draw must complete, not deadlock.
        let handle = LimitHandle::with_limit(1_000_000);
        let elapsed = drain(&handle, 2_000_000, 2_000_000).await.as_secs_f64();
        assert!(
            elapsed >= 1.9,
            "a 2 MB draw at 1 MB/s should take about 2s, took {elapsed}s"
        );
    }
}
