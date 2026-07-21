//! The download engine handle.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::FetchError;
use crate::job::Job;
use crate::limiter::LimitHandle;
use crate::probe::CapabilityCache;
use crate::progress::Progress;
use crate::scheduler::Scheduler;
use crate::spec::DownloadSpec;
use crate::validator::{Validator, VerifiedFile};

/// The default connection-inactivity timeout before a segment is re-queued.
const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_secs(15);

/// State shared by every clone of a [`Fetcher`]: the job/connection scheduler, the speed limiter, the
/// per-host capability cache, and the segmentation config. Cloning the fetcher is cheap and shares all
/// of it, so the caps and the cache hold across concurrently submitted jobs.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) scheduler: Arc<Scheduler>,
    pub(crate) limiter: LimitHandle,
    pub(crate) capabilities: CapabilityCache,
    pub(crate) max_connections_per_file: usize,
    pub(crate) stall_timeout: Duration,
}

/// A resumable, verified downloader. A cheap handle over a pooled HTTP client and the shared
/// scheduler/limiter: clone it to hand to several consumers.
#[derive(Debug, Clone)]
pub struct Fetcher {
    client: reqwest::Client,
    shared: Arc<Shared>,
}

impl Fetcher {
    /// Start configuring a [`Fetcher`].
    #[must_use]
    pub fn builder() -> FetcherBuilder {
        FetcherBuilder::default()
    }

    /// Construct a fetcher over a caller-supplied client. Test-only (gated behind the `testing`
    /// feature, never compiled into a release build): it lets a test inject a client that trusts a
    /// loopback test certificate, which the safe builder deliberately cannot be configured to do.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn from_client(client: reqwest::Client) -> Self {
        Self {
            client,
            shared: FetcherBuilder::default().shared(),
        }
    }

    /// Download `spec`'s source to its destination, returning proof it verified.
    ///
    /// Progress snapshots are sent on `progress` when provided; the sender is dropped when the
    /// download ends, closing a consumer's stream. `cancel` aborts the transfer, leaving the partial
    /// file and its journal for a later resume. The job is admitted through the shared scheduler at
    /// `spec`'s priority, so it waits its turn when the fetcher is already at its concurrency cap.
    ///
    /// # Errors
    /// A [`FetchError`] for any transport, length, verification, i/o, or cancellation failure, or
    /// [`FetchError::Unsupported`] if `spec` carries [`Validator::External`] (that marker never yields
    /// a [`VerifiedFile`]; use [`download_external`](Self::download_external)).
    pub async fn download(
        &self,
        spec: &DownloadSpec,
        progress: Option<mpsc::UnboundedSender<Progress>>,
        cancel: CancellationToken,
    ) -> Result<VerifiedFile, FetchError> {
        if matches!(spec.validator(), Validator::External) {
            return Err(FetchError::Unsupported {
                what: "Validator::External must be fetched through download_external",
            });
        }
        let _job = self.shared.scheduler.acquire_job(spec.priority()).await;
        crate::segmented::dispatch(&self.client, spec, progress, cancel, &self.shared).await
    }

    /// Download `spec`'s externally-verified source and hand back the landed path, never a
    /// [`VerifiedFile`]. The bytes are length-checked during the transfer; a named downstream gate
    /// authenticates them (a boot patch's ZiPatch chunk-CRC scan, run by `apogee-patcher`). This is
    /// the one sanctioned way to fetch plain-HTTP bytes with no fetch-side hash: `spec` must carry
    /// [`Validator::External`], whose spec-build rules already require a declared length.
    ///
    /// Progress and cancellation behave exactly as in [`download`](Self::download).
    ///
    /// # Errors
    /// [`FetchError::Unsupported`] if `spec`'s validator is not [`Validator::External`]; otherwise any
    /// transport, length, i/o, or cancellation [`FetchError`].
    pub async fn download_external(
        &self,
        spec: &DownloadSpec,
        progress: Option<mpsc::UnboundedSender<Progress>>,
        cancel: CancellationToken,
    ) -> Result<PathBuf, FetchError> {
        if !matches!(spec.validator(), Validator::External) {
            return Err(FetchError::Unsupported {
                what: "download_external requires Validator::External",
            });
        }
        let _job = self.shared.scheduler.acquire_job(spec.priority()).await;
        // The `External` plan verifies nothing beyond length, so the proof `dispatch` mints is over
        // length-checked bytes only; it is unwrapped to a bare path here and never handed out, so no
        // consumer receives a `VerifiedFile` the bytes did not earn.
        let landed =
            crate::segmented::dispatch(&self.client, spec, progress, cancel, &self.shared).await?;
        Ok(landed.path().to_path_buf())
    }

    /// Submit `spec` to run on the scheduler, returning a [`Job`] handle to watch its progress, cancel
    /// it, and await its verified result. Unlike [`download`](Self::download), the transfer runs on a
    /// spawned task, so several jobs can be submitted and awaited concurrently under the shared caps.
    #[must_use]
    pub fn submit(&self, spec: DownloadSpec) -> Job {
        let cancel = CancellationToken::new();
        let (tx, rx) = mpsc::unbounded_channel();
        // `External` never yields a `VerifiedFile`, and a `Job` resolves to one, so refuse it here
        // (as `download` does) rather than mint a proof the bytes did not earn.
        if matches!(spec.validator(), Validator::External) {
            drop(tx);
            let handle = tokio::spawn(async move {
                Err(FetchError::Unsupported {
                    what: "Validator::External must be fetched through download_external",
                })
            });
            return Job::new(handle, rx, cancel);
        }
        let client = self.client.clone();
        let shared = Arc::clone(&self.shared);
        let job_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            let _job = shared.scheduler.acquire_job(spec.priority()).await;
            crate::segmented::dispatch(&client, &spec, Some(tx), job_cancel, &shared).await
        });
        Job::new(handle, rx, cancel)
    }

    /// Fetch a set of byte `ranges` (sorted, non-overlapping) of one `url`, delivering each fetched
    /// span to `sink` as `(absolute_offset, bytes)`. `expected_len` is the source file's length,
    /// cross-checked against each response's `Content-Range` total. This is the low-level scatter-
    /// gather primitive behind repair; [`HttpRangeSource`](crate::HttpRangeSource) wraps it to
    /// implement `apogee-zipatch`'s range seam.
    ///
    /// Ranges are packed into requests under `packing` (a count cap and a `Range` header byte budget),
    /// and each response is handled whether it is a single `206`, a `multipart/byteranges` body, or a
    /// range-ignoring `200`. A single attempt against one URL: mirror rotation and retry live in the
    /// caller.
    ///
    /// # Errors
    /// A [`FetchError`] for any transport, HTTP-status, length, or malformed-response fault, or the
    /// sink's own error propagated verbatim.
    pub async fn fetch_ranges<F>(
        &self,
        url: &url::Url,
        expected_len: u64,
        ranges: &[std::ops::Range<u64>],
        policy: Option<&crate::HeaderPolicy>,
        packing: crate::RangePacking,
        sink: F,
    ) -> Result<(), FetchError>
    where
        F: FnMut(u64, &[u8]) -> Result<(), FetchError>,
    {
        let engine = crate::ranges::Engine {
            client: &self.client,
            shared: &self.shared,
        };
        crate::ranges::fetch_ranges(&engine, url, expected_len, ranges, policy, packing, sink).await
    }
}

/// Builder for a [`Fetcher`]: the concurrency caps and the shared speed limit. `build()` with no
/// knobs set produces the reference-parity defaults (4 files, 8 connections per file, 24 total,
/// uncapped).
#[derive(Debug)]
pub struct FetcherBuilder {
    max_files: usize,
    max_connections_per_file: usize,
    max_connections_total: usize,
    speed_limit: Option<LimitHandle>,
    stall_timeout: Duration,
}

impl Default for FetcherBuilder {
    fn default() -> Self {
        Self {
            max_files: 4,
            max_connections_per_file: 8,
            max_connections_total: 24,
            speed_limit: None,
            stall_timeout: DEFAULT_STALL_TIMEOUT,
        }
    }
}

impl FetcherBuilder {
    /// The number of jobs downloaded concurrently (default 4).
    #[must_use]
    pub fn max_files(mut self, n: usize) -> Self {
        self.max_files = n;
        self
    }

    /// The number of connections a single segmented file may open (default 8).
    #[must_use]
    pub fn max_connections_per_file(mut self, n: usize) -> Self {
        self.max_connections_per_file = n;
        self
    }

    /// The global cap on open connections across all jobs (default 24).
    #[must_use]
    pub fn max_connections_total(mut self, n: usize) -> Self {
        self.max_connections_total = n;
        self
    }

    /// Share a live-adjustable speed limit across this fetcher's transfers. Absent means uncapped.
    #[must_use]
    pub fn speed_limit(mut self, limit: LimitHandle) -> Self {
        self.speed_limit = Some(limit);
        self
    }

    /// How long a segment connection may make no progress before it is killed and re-queued
    /// (default 15 s). A dead CDN node is detected by this inactivity timeout.
    #[must_use]
    pub fn stall_timeout(mut self, timeout: Duration) -> Self {
        self.stall_timeout = timeout;
        self
    }

    /// Assemble the shared scheduler/limiter/cache from the configured caps.
    fn shared(&self) -> Arc<Shared> {
        Arc::new(Shared {
            scheduler: Arc::new(Scheduler::new(self.max_files, self.max_connections_total)),
            limiter: self
                .speed_limit
                .clone()
                .unwrap_or_else(LimitHandle::uncapped),
            capabilities: CapabilityCache::default(),
            max_connections_per_file: self.max_connections_per_file.max(1),
            stall_timeout: self.stall_timeout,
        })
    }

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
            // Keep enough idle connections alive to reuse across a file's segments.
            .pool_max_idle_per_host(self.max_connections_per_file)
            .build()
            .map_err(|e| FetchError::Client {
                source: std::io::Error::other(e),
            })?;
        let shared = self.shared();
        Ok(Fetcher { client, shared })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::Validator;
    use url::Url;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    // Both guards fire before any scheduler or network contact, so these need no server.

    #[tokio::test]
    async fn download_refuses_external_and_points_at_download_external() {
        let fetcher = Fetcher::builder().build().unwrap();
        let spec = DownloadSpec::builder(
            url("http://patch.invalid/boot.patch"),
            "/tmp/b",
            Validator::External,
        )
        .expected_len(10)
        .build()
        .unwrap();
        let err = fetcher
            .download(&spec, None, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Unsupported { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn download_external_requires_the_external_marker() {
        let fetcher = Fetcher::builder().build().unwrap();
        let spec = DownloadSpec::builder(
            url("https://host.invalid/f"),
            "/tmp/f",
            Validator::Sha256([0; 32]),
        )
        .expected_len(10)
        .build()
        .unwrap();
        let err = fetcher
            .download_external(&spec, None, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Unsupported { .. }), "got {err:?}");
    }
}
