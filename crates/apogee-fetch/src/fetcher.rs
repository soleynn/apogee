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
use crate::progress::{Progress, Reporter};
use crate::retry::{Jitter, RetryPolicy};
use crate::scheduler::Scheduler;
use crate::spec::DownloadSpec;
use crate::validator::{Validator, VerifiedFile};

/// The default connection-inactivity timeout before a transfer is re-queued.
const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_secs(15);

/// The HTTP/2 flow-control window advertised for a connection and for each stream on it.
const H2_WINDOW: u32 = 16 * 1024 * 1024;

/// State shared by every clone of a [`Fetcher`]: the job/connection scheduler, the speed limiter, the
/// per-host capability cache, the retry policy and its jitter source, and the segmentation config.
/// Cloning the fetcher is cheap and shares all of it, so the caps and the cache hold across
/// concurrently submitted jobs.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) scheduler: Arc<Scheduler>,
    pub(crate) limiter: LimitHandle,
    pub(crate) capabilities: CapabilityCache,
    pub(crate) max_connections_per_file: usize,
    pub(crate) stall_timeout: Duration,
    pub(crate) retry: RetryPolicy,
    /// One jitter source per fetcher, so every retry site of every job draws from a generator seeded
    /// once rather than one seeded per transfer.
    pub(crate) jitter: Arc<Jitter>,
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
        crate::segmented::dispatch(
            &self.client,
            spec,
            Reporter::new(progress),
            cancel,
            &self.shared,
        )
        .await
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
        let landed = crate::segmented::dispatch(
            &self.client,
            spec,
            Reporter::new(progress),
            cancel,
            &self.shared,
        )
        .await?;
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
            crate::segmented::dispatch(&client, &spec, Reporter::new(Some(tx)), job_cancel, &shared)
                .await
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
/// knobs set produces the shipped defaults (4 files, 6 segments in flight per file, 24 in flight in
/// total, uncapped).
#[derive(Debug)]
pub struct FetcherBuilder {
    max_files: usize,
    max_connections_per_file: usize,
    max_connections_total: usize,
    speed_limit: Option<LimitHandle>,
    stall_timeout: Duration,
    retry: RetryPolicy,
    /// DER roots a test fixture asks the client to trust, beside (never instead of) the system
    /// store. Exists only under the `testing` feature; a release build has no way to hold one.
    #[cfg(feature = "testing")]
    extra_roots: Vec<Vec<u8>>,
}

impl Default for FetcherBuilder {
    /// The three caps must satisfy `max_files * max_connections_per_file <= max_connections_total`,
    /// so that every admitted file can run all of its segments and no segment worker ever parks on the
    /// global semaphore. Changing any one of them without the others is what breaks it.
    ///
    /// 4 x 8 against a total of 24 broke it, and left a quarter of the workers waiting: over a live
    /// 207-patch install, 13 patches went 16 to 35 s between successive per-file progress frames while
    /// aggregate throughput stayed at the link rate. Silence more than twice the stall timeout reads
    /// exactly like the failure it is not, so a per-file progress bar built on that stream is
    /// unreadable.
    ///
    /// The per-file cap gives way rather than the total, because 24 in flight is the request count
    /// that same install measured at line rate, and because connection count is not a throughput lever
    /// on these hosts: an h2 source serves every segment as a stream on one socket regardless. The cost
    /// is a file split 6 ways instead of 8, paid in a dimension nothing measured cared about.
    fn default() -> Self {
        Self {
            max_files: 4,
            max_connections_per_file: 6,
            max_connections_total: 24,
            speed_limit: None,
            stall_timeout: DEFAULT_STALL_TIMEOUT,
            retry: RetryPolicy::default(),
            #[cfg(feature = "testing")]
            extra_roots: Vec::new(),
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

    /// How many segments of one file are in flight at once, and so how many segments it is split into
    /// (default 6, chosen against the other two caps: see [`FetcherBuilder::default`]).
    ///
    /// Named for connections because that is what it costs against an HTTP/1.1 source: one per
    /// segment. An h2 host serves all of them as streams on a single connection instead, so the
    /// sockets a transfer opens are the server's choice and this is the request count either way.
    #[must_use]
    pub fn max_connections_per_file(mut self, n: usize) -> Self {
        self.max_connections_per_file = n;
        self
    }

    /// The global cap on transfer requests in flight across all jobs (default 24), one socket each
    /// against an HTTP/1.1 source and streams on one connection against an h2 host. Keep it at or above
    /// `max_files * max_connections_per_file`, or segment workers park on it: see
    /// [`FetcherBuilder::default`].
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

    /// How long a connection may make no progress before it is killed and re-queued (default 15 s).
    /// A dead CDN node is detected by this inactivity timeout, on both the segmented and the
    /// single-connection path.
    ///
    /// "No progress" covers a request from the moment it is sent: reaching the host, and then waiting
    /// for its response headers, are bounded by this too, so a host that accepts a connection and
    /// then says nothing costs one attempt rather than hanging the transfer.
    #[must_use]
    pub fn stall_timeout(mut self, timeout: Duration) -> Self {
        self.stall_timeout = timeout;
        self
    }

    /// How this fetcher's transfers back off and how many attempts each stuck range gets (default
    /// [`RetryPolicy::default`]). One policy covers every retry site: a dropped or silent connection,
    /// a block that failed its hash, the range probe, and a throttling server.
    #[must_use]
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry = policy;
        self
    }

    /// Trust one additional root certificate (DER), for a test standing up a loopback TLS fixture.
    /// Test-only (gated behind the `testing` feature, never compiled into a release build) and
    /// outside the crate's version commitment, which covers the default feature set. This is
    /// dependency injection, not a certificate bypass: the built client still validates the server
    /// against that root, and everything else about it is exactly what ships, the shipped redirect
    /// policy and flow-control window included, so a test through this knob exercises the real
    /// client rather than a hand-rebuilt approximation.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn extra_root_certificate(mut self, der: &[u8]) -> Self {
        self.extra_roots.push(der.to_vec());
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
            retry: self.retry,
            jitter: Arc::new(Jitter::new()),
        })
    }

    /// Build the configured [`Fetcher`].
    ///
    /// # Errors
    /// [`FetchError::Config`] if `max_files * max_connections_per_file` exceeds
    /// `max_connections_total` (see [`FetcherBuilder::default`] for why that combination cannot be
    /// served); [`FetchError::Client`] if the HTTP client cannot be constructed.
    pub fn build(self) -> Result<Fetcher, FetchError> {
        // The scheduler clamps each cap to at least 1, so the invariant is checked over the values
        // that will actually run.
        let (files, per_file, total) = (
            self.max_files.max(1),
            self.max_connections_per_file.max(1),
            self.max_connections_total.max(1),
        );
        if files * per_file > total {
            return Err(FetchError::Config {
                detail: format!(
                    "{files} file(s) x {per_file} connection(s) per file exceeds the global cap of \
                     {total}: admitted files would park segment workers on the semaphore and go \
                     silent while the others transfer",
                ),
            });
        }
        let client_builder = reqwest::Client::builder()
            // Keep the on-wire bytes identical to the body bytes: verification and the length
            // cross-check must see exactly what the server sent, never a transparently decoded stream.
            .gzip(false)
            .deflate(false)
            // Keep enough idle connections alive to reuse across a file's segments.
            .pool_max_idle_per_host(self.max_connections_per_file)
            // Advertise a 16 MiB flow-control window, well past hyper's 5 MiB connection and 2 MiB
            // stream defaults. Everything fetched over TLS negotiates HTTP/2, and a download whose
            // length the caller does not declare runs on the single-connection engine, so its whole
            // body arrives on one stream and that 2 MiB window, rather than the link, is what sets
            // its speed: on a 1 Gb/s line 15 ms from the host's edge, a 532 MB release asset landed
            // at 50-52 MiB/s through this builder on the defaults and 70-74 MiB/s at 16 MiB, and a
            // 59 MB asset on an unrelated CDN moved the same way. The size is where the window stops
            // being the limit rather than a guess: discarding the same body instead of writing it,
            // 16 MiB reaches 71-89 MiB/s against the 82-86 MiB/s the identical transfer gets over
            // HTTP/1.1, which has no window at all, and 64 MiB measures no better while promising to
            // buffer four times as much unread body per connection. Letting the window retune itself
            // is the other way to raise it and is not taken: it swung run to run. Cleartext transfers
            // are HTTP/1.1 and none of this reaches them.
            .http2_initial_stream_window_size(H2_WINDOW)
            .http2_initial_connection_window_size(H2_WINDOW)
            // Neither `timeout` nor `connect_timeout` is set here, and both are deliberate. The first
            // covers the response body, so it would cut a multi-gigabyte transfer off at a fixed
            // duration rather than at a fixed silence. The second would bound only what
            // `download::send_bounded` already bounds from the outside, off a clock that starts a
            // moment later at the same length, so the two would race to name the same failure and a
            // hung connect would report `Connect` or `Stalled` depending on which timer's tick landed
            // first. One deadline, around the whole of each `send`, is what makes that answer
            // deterministic.
            .redirect(crate::redirect::policy())
            // The origin URL is none of the redirect target's business. reqwest adds a `Referer`
            // carrying it by default, which hands a third-party host the full path a transfer
            // started from, including a patch file's name. Nothing we fetch needs one.
            .referer(false);
        #[cfg(feature = "testing")]
        let client_builder = self.extra_roots.iter().try_fold(client_builder, |b, der| {
            reqwest::Certificate::from_der(der)
                .map(|cert| b.add_root_certificate(cert))
                .map_err(|e| FetchError::Client {
                    source: std::io::Error::other(e),
                })
        })?;
        let client = client_builder.build().map_err(|e| FetchError::Client {
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

    #[test]
    fn the_shipped_caps_let_every_admitted_file_run_all_its_segments() {
        let b = FetcherBuilder::default();
        assert!(
            b.max_files * b.max_connections_per_file <= b.max_connections_total,
            "{} files x {} segments exceeds the global cap of {}, so {} segment workers would park on \
             the semaphore and their files would go silent while the others transfer",
            b.max_files,
            b.max_connections_per_file,
            b.max_connections_total,
            b.max_files * b.max_connections_per_file - b.max_connections_total,
        );
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
