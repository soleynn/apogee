//! The download engine handle.

use crate::error::FetchError;

/// A resumable, verified downloader. A cheap handle over a pooled HTTP client: clone it to hand to
/// several consumers.
#[derive(Debug, Clone)]
pub struct Fetcher {
    // The pooled client and the streaming download path land with the transfer engine.
}

impl Fetcher {
    /// Start configuring a [`Fetcher`].
    #[must_use]
    pub fn builder() -> FetcherBuilder {
        FetcherBuilder::default()
    }
}

/// Builder for a [`Fetcher`]. Scheduling and rate-limiting knobs return with the multi-connection
/// scheduler; a single-connection downloader has nothing to tune yet.
#[derive(Debug, Default)]
pub struct FetcherBuilder {}

impl FetcherBuilder {
    /// Build the configured [`Fetcher`].
    ///
    /// # Errors
    /// A [`FetchError`] if the underlying HTTP client cannot be constructed.
    pub fn build(self) -> Result<Fetcher, FetchError> {
        Ok(Fetcher {})
    }
}
