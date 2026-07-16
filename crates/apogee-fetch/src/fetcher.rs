//! The download engine handle.

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::FetchError;
use crate::progress::Progress;
use crate::spec::DownloadSpec;
use crate::validator::VerifiedFile;

/// A resumable, verified downloader. A cheap handle over a pooled HTTP client: clone it to hand to
/// several consumers.
#[derive(Debug, Clone)]
pub struct Fetcher {
    client: reqwest::Client,
}

impl Fetcher {
    /// Start configuring a [`Fetcher`].
    #[must_use]
    pub fn builder() -> FetcherBuilder {
        FetcherBuilder::default()
    }

    /// Download `spec`'s source to its destination, returning proof it verified.
    ///
    /// Progress snapshots are sent on `progress` when provided; the sender is dropped when the
    /// download ends, closing a consumer's stream. `cancel` aborts the transfer, leaving the partial
    /// file and its journal for a later resume.
    ///
    /// # Errors
    /// A [`FetchError`] for any transport, length, verification, i/o, or cancellation failure.
    pub async fn download(
        &self,
        spec: &DownloadSpec,
        progress: Option<mpsc::UnboundedSender<Progress>>,
        cancel: CancellationToken,
    ) -> Result<VerifiedFile, FetchError> {
        crate::download::run(&self.client, spec, progress, cancel).await
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
    /// [`FetchError::Client`] if the HTTP client cannot be constructed.
    pub fn build(self) -> Result<Fetcher, FetchError> {
        let client = reqwest::Client::builder()
            // Keep the on-wire bytes identical to the body bytes: verification and the length
            // cross-check must see exactly what the server sent, never a transparently decoded stream.
            .gzip(false)
            .deflate(false)
            .build()
            .map_err(|e| FetchError::Client {
                source: std::io::Error::other(e),
            })?;
        Ok(Fetcher { client })
    }
}
