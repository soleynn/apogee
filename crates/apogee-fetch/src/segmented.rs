//! The segmented transfer engine and the single/segmented dispatch.
//!
//! A file of known length whose host serves ranges is divided into segments, each pulled by its own
//! worker writing at its own offset into one preallocated `.part`. A work queue plus that pool of
//! workers is the whole mechanism: a segment that stalls or drops re-queues the *remaining* bytes of
//! its own range (nothing already durable is lost), and the completed-interval journal lets the whole
//! transfer resume across a restart. When the length is unknown, the file is small, or the host
//! ignores ranges, the transfer falls back to the single-connection engine in [`crate::download`].
//!
//! **What a segment costs in sockets is the server's decision, not this engine's.** Over HTTP/1.1
//! each concurrent segment needs a connection of its own; an h2 host multiplexes every one of them
//! onto a single connection, where they are streams sharing one congestion window. So the caps and
//! slots named for connections, here and on the scheduler, bound *concurrent segment requests*, which
//! is the same number as connections only in the first case.
//!
//! Re-queued work does not have to go back to the source that failed it. Every unit of work carries
//! the source it was asked from, and every failure of it - a refused connection, a dropped body, a
//! silence past the stall timeout, a throttling status, a block that failed its hash - steps that
//! choice along the spec's source list by the same rule ([`rotate`](crate::retry::rotate)), which the
//! single-connection engine's retry path shares. A mirror that turns out not to serve ranges at all is
//! taken out of the rotation for the rest of the transfer rather than being re-asked for every later
//! block.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::SeekFrom;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{CONTENT_RANGE, ETAG, IF_RANGE, LAST_MODIFIED, RANGE};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::block::{self, BlockVerify};
use crate::download::{self, Verify};
use crate::error::FetchError;
use crate::fetcher::Shared;
use crate::hash::DigestPin;
use crate::headers::{HeaderPolicy, apply_headers};
use crate::intervals::IntervalSet;
use crate::journal::{self, Identity, Journal};
use crate::prealloc::preallocate;
use crate::probe::{Capability, classify};
use crate::progress::{Phase, Reporter};
use crate::retry::{
    Class, Jitter, RetryPolicy, classify_send_error, classify_status, retry_after, rotate,
    sleep_or_cancel,
};
use crate::spec::DownloadSpec;
use crate::util::lock;
use crate::validator::VerifiedFile;

/// Bytes streamed between `fsync` + journal-commit points within a segment (the resume granularity).
const BATCH: u64 = 1024 * 1024;
/// The floor on segment size; a file no larger than this is not worth splitting.
const MIN_SEGMENT: u64 = 8 * 1024 * 1024;

/// How many block hashes may run on the shared blocking pool at once. Bounded to the host's parallelism
/// (capped) so a burst of newly-durable blocks never starves the transfer's own disk I/O.
fn hash_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 16)
}

/// One unit of transfer work: a byte range and which source to fetch it from (`0` is the primary,
/// higher indices are mirrors). A re-queue re-picks the source from the work's own attempt count.
struct Task {
    range: Range<u64>,
    source: usize,
}

/// Decide single vs segmented and run the transfer. The single-connection engine owns the
/// unknown-length, small-file, and range-ignored (demoted) cases; the segmented engine owns the rest.
pub(crate) async fn dispatch(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    progress: Reporter,
    cancel: CancellationToken,
    shared: &Shared,
) -> Result<VerifiedFile, FetchError> {
    let verify = download::plan(spec.validator(), spec.expected_len())?;

    let Some(len) = spec.expected_len() else {
        return download::run(client, spec, verify, progress, cancel, shared).await;
    };
    let per_file = shared.max_connections_per_file;
    let seg_size = (len / per_file as u64).max(MIN_SEGMENT);
    let block_mode = verify.blocks.is_some();
    // A small whole-file transfer stays single-connection. Block mode keeps the ranged engine even for
    // one segment: its dirty-block re-fetch rides that engine's work queue, so it demotes only when the
    // host ignores ranges (handled below).
    if (per_file <= 1 || len.div_ceil(seg_size) <= 1) && !block_mode {
        return download::run(client, spec, verify, progress, cancel, shared).await;
    }

    // Skip a satisfied destination before spending a probe request.
    if let Some(verified) =
        download::check_existing_dest(spec.dest(), &verify, Some(len), &progress).await?
    {
        return Ok(verified);
    }

    let probed = match shared.capabilities.get(spec.url()) {
        // The cache is keyed per host, so a hit is always the primary's own verdict. It knows only
        // the capability though, not the URL's validators (which are per-URL, not per-host), so a
        // cache-hit download records none; a resume then relies on the whole-file hash to catch a
        // changed source.
        Some(capability) => Probe {
            capability,
            source: 0,
            etag: None,
            last_modified: None,
        },
        None => {
            let probed = probe(client, spec, &progress, &cancel, shared).await?;
            shared
                .capabilities
                .set(&spec.sources()[probed.source], probed.capability);
            // Validators are per URL, not per host, so only the primary's own probe records them: a
            // probe answered by a mirror describes that mirror's copy, and offering it back to the
            // primary as an `If-Range` would invite a changed-source verdict on a source that never
            // changed.
            match probed.source {
                0 => probed,
                _ => Probe {
                    etag: None,
                    last_modified: None,
                    ..probed
                },
            }
        }
    };
    let from_primary = probed.source == 0;
    match probed.capability {
        // A range-ignoring host cannot serve a block re-fetch; the single-connection engine verifies
        // block mode from disk after streaming the whole file (no targeted repair). Only the primary's
        // own verdict demotes: a mirror's answer settles nothing about the host the transfer starts
        // from, and a range-ignoring mirror is the segmented engine's own business (it passes over it).
        //
        // Demotion stays a verdict about the primary rather than an excuse to go looking for a mirror
        // that would segment. Mirrors are the fallbacks the spec names, so a primary that merely
        // serves slower than one of them still serves, and re-probing to find out would spend a
        // request per source before a byte was asked for. What demotion costs the job is throughput,
        // not availability: the single-connection engine rotates through this same source list on
        // failure, so a demoted transfer whose primary then dies still finishes off a mirror.
        Capability::SingleConnection if from_primary => {
            progress.counters().demote();
            tracing::info!(
                url = %spec.url(),
                len,
                seg_size,
                "the primary ignored the probe's range; streaming on one connection instead",
            );
            download::run(client, spec, verify, progress, cancel, shared).await
        }
        Capability::SingleConnection | Capability::Segmentable => {
            transfer(
                client,
                spec,
                len,
                seg_size,
                verify,
                probed.etag,
                probed.last_modified,
                progress,
                cancel,
                shared,
            )
            .await
        }
    }
}

/// A probe's verdict, which source gave it, and the server validators to record for a later resume's
/// `If-Range`.
struct Probe {
    capability: Capability,
    /// The source that answered: `0` for the primary, higher for a mirror the probe fell through to.
    source: usize,
    etag: Option<Vec<u8>>,
    last_modified: Option<Vec<u8>>,
}

/// Probe range support with a one-byte ranged request, classifying the response and capturing its
/// validators, then dropping its body (so a range-ignoring `200` wastes only a socket buffer, never
/// the whole file).
///
/// The probe is the transfer's first request, so a throttled or restarting host would otherwise fail
/// a whole job before a byte was asked for: a connect failure or a retryable status backs off here
/// under the same policy the segment workers use, and rotates through the sources by the same rule,
/// so a primary that is down cannot fail a job the mirrors could have served. Exhausting the budget
/// reports the last source's own failure, which names a host and carries the cause.
async fn probe(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    progress: &Reporter,
    cancel: &CancellationToken,
    shared: &Shared,
) -> Result<Probe, FetchError> {
    let sources = spec.sources();
    let mut attempts = 0u32;
    loop {
        let source = rotate(attempts, sources.len());
        let url = &sources[source];
        let request =
            apply_headers(client.get(url.clone()), spec.header_policy()).header(RANGE, "bytes=0-0");
        let sent = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(FetchError::Cancelled),
            sent = download::send_bounded(request, shared.stall_timeout) => sent,
        };
        // Each arm yields the failure to report if this is the last attempt, plus the pause the
        // server asked for; a usable response returns straight out.
        let (failure, asked) = match sent {
            // No headers within the deadline. The probe has no bytes of its own to be short of, so
            // the stall it reports is at zero: the transfer never started.
            Err(_elapsed) => {
                progress.counters().stall();
                tracing::warn!(
                    url = %url,
                    timeout_ms = shared.stall_timeout.as_millis(),
                    "the capability probe got no response headers within the deadline",
                );
                (
                    FetchError::Stalled {
                        url: url.clone(),
                        at_bytes: 0,
                    },
                    None,
                )
            }
            Ok(Ok(resp)) => match resp.status().as_u16() {
                200 | 206 => {
                    return Ok(Probe {
                        etag: download::header_bytes(&resp, &ETAG),
                        last_modified: download::header_bytes(&resp, &LAST_MODIFIED),
                        capability: classify(&resp),
                        source,
                    });
                }
                status if classify_status(status) == Class::Retryable => (
                    FetchError::Http {
                        status,
                        url: url.clone(),
                    },
                    retry_after(resp.headers()),
                ),
                status => {
                    return Err(FetchError::Http {
                        status,
                        url: url.clone(),
                    });
                }
            },
            Ok(Err(e)) if classify_send_error(&e) == Class::Fatal => {
                return Err(download::connect_error(url, e));
            }
            Ok(Err(e)) => (download::connect_error(url, e), None),
        };
        attempts += 1;
        if !shared.retry.may_retry(attempts) {
            tracing::warn!(
                url = %url,
                attempts,
                reason = %failure,
                "the capability probe exhausted its attempt budget",
            );
            return Err(failure);
        }
        let to = rotate(attempts, sources.len());
        progress.counters().retry(source, to);
        let delay = shared.retry.delay(attempts, asked, &shared.jitter);
        tracing::debug!(
            url = %url,
            attempts,
            from = source,
            to,
            delay_ms = delay.as_millis(),
            reason = %failure,
            "retrying the capability probe after a backoff",
        );
        if !sleep_or_cancel(delay, cancel).await {
            return Err(FetchError::Cancelled);
        }
    }
}

/// Shared state for one segmented transfer: the work queue, the durable-byte counter, the journal, and
/// the terminal outcome. One `Arc` is held by every worker plus the progress aggregator.
struct TransferState {
    client: reqwest::Client,
    /// The primary URL, followed by any mirrors: a [`Task`]'s `source` indexes this list. Index `0` is
    /// the primary and the resume identity key, so rotating to a mirror never invalidates the journal.
    sources: Vec<Url>,
    part: PathBuf,
    apdl: PathBuf,
    len: u64,
    stall_timeout: Duration,
    header_policy: Option<HeaderPolicy>,
    /// The `If-Range` value (ETag or Last-Modified) sent on resume, or `None` on a fresh transfer.
    if_range: Option<Vec<u8>>,
    limiter: crate::limiter::LimitHandle,
    scheduler: Arc<crate::scheduler::Scheduler>,
    /// The progress channel and this transfer's recovery counters. Held here rather than passed to
    /// each worker: a re-queue, a dropped mirror and a dirty block are all counted deep inside the
    /// worker tree, where the reporter is the one thing already reachable through `state`.
    reporter: Reporter,
    /// How a re-queued range or a dirty block waits, and how many attempts each gets.
    retry: RetryPolicy,
    jitter: Arc<Jitter>,
    queue: Mutex<VecDeque<Task>>,
    notify: Notify,
    progress_notify: Notify,
    durable: AtomicU64,
    /// The live durable byte set (not just its length), so the block verifier can tell which whole
    /// blocks are on disk. Seeded from the resume set; grown in `commit_batch`, shrunk when a dirty
    /// block is cleared. Its length always equals `durable`.
    covered: Mutex<IntervalSet>,
    attempts: Mutex<HashMap<u64, u32>>,
    /// Sources found unable to serve byte ranges, by index. A mirror that answers a ranged request
    /// with a whole body cannot serve a segment or a block repair, and it will answer the next one
    /// the same way, so the verdict is taken once and holds for the rest of the transfer instead of
    /// costing every later block a wasted request. Index `0` is never in here: a whole body from the
    /// primary is a changed source, not a capability, and that is what leaves at least one source
    /// always eligible.
    ranges_ignored: Mutex<HashSet<usize>>,
    journal: tokio::sync::Mutex<Option<Journal>>,
    /// Present only in block mode: the per-block verification state and its wake channel.
    verify: Option<Arc<BlockVerify>>,
    /// Caps how many block hashes run on the shared blocking pool at once, so a burst of newly-durable
    /// blocks (e.g. resuming a fully-durable multi-thousand-block patch) cannot starve the transfer's
    /// own disk I/O, which shares that pool.
    hash_limit: Arc<Semaphore>,
    done: CancellationToken,
    end: Mutex<Option<Result<(), FetchError>>>,
}

impl TransferState {
    /// Record the terminal outcome (first writer wins) and wake every task by firing `done`.
    fn finish(&self, result: Result<(), FetchError>) {
        let mut end = lock(&self.end);
        if end.is_none() {
            *end = Some(result);
            self.done.cancel();
        }
    }

    /// The primary source (index `0`): the resume identity key and the target for top-level errors.
    fn primary(&self) -> &Url {
        &self.sources[0]
    }

    /// This transfer's recovery counters.
    fn counters(&self) -> &crate::progress::Counters {
        self.reporter.counters()
    }

    /// The source work used on its previous try and the one its `attempts`-th failure sends it to.
    ///
    /// Both ends come from the same rotation over the same eligible set, and the attempt count is
    /// keyed to the unit of work, so the pair is exact rather than a guess: at one failure the two
    /// are equal (the free same-source retry) and they diverge on the step that reaches a mirror.
    fn rotation(&self, attempts: u32) -> (usize, usize) {
        (
            self.next_source(attempts.saturating_sub(1)),
            self.next_source(attempts),
        )
    }

    /// Push a pending task and wake one waiting worker. An empty range is dropped.
    fn push_task(&self, task: Task) {
        if task.range.start >= task.range.end {
            return;
        }
        lock(&self.queue).push_back(task);
        self.notify.notify_one();
    }

    /// Take the next pending task, waiting for one to appear. `None` when the transfer is finished or
    /// cancelled (never inferred from an empty queue, so a mid-re-queue gap cannot end the job early).
    async fn pop_or_wait(&self, cancel: &CancellationToken) -> Option<Task> {
        loop {
            if let Some(task) = lock(&self.queue).pop_front() {
                return Some(task);
            }
            // Register interest before the final re-check so a push between the two cannot be lost.
            let notified = self.notify.notified();
            if let Some(task) = lock(&self.queue).pop_front() {
                return Some(task);
            }
            tokio::select! {
                biased;
                () = self.done.cancelled() => return None,
                () = cancel.cancelled() => return None,
                () = notified => {}
            }
        }
    }

    /// Increment and return the attempt count for a stuck offset.
    ///
    /// The key is the offset the re-queued range starts at, so the count measures consecutive
    /// failures that gained *no bytes*: a source that delivered part of a segment moves the key
    /// along, which resets both the budget and the rotation back to the primary. Only work that is
    /// genuinely stuck escalates through the source list.
    fn bump_attempt(&self, start: u64) -> u32 {
        let mut attempts = lock(&self.attempts);
        let counter = attempts.entry(start).or_insert(0);
        *counter += 1;
        *counter
    }

    /// Record that `source` answered a ranged request with a whole body, so later picks pass over it.
    /// `true` when this call is what recorded it, `false` for a worker that raced to the same verdict.
    fn mark_ranges_ignored(&self, source: usize) -> bool {
        lock(&self.ranges_ignored).insert(source)
    }

    /// The first source at or after `from`, wrapping, that has not been found unable to serve ranges.
    /// Total: the primary is never marked, so the walk always lands somewhere within one lap.
    fn eligible_from(&self, from: usize) -> usize {
        let count = self.sources.len();
        let ignored = lock(&self.ranges_ignored);
        (0..count)
            .map(|step| (from + step) % count)
            .find(|source| !ignored.contains(source))
            .unwrap_or(0)
    }

    /// Which source to ask for work that has failed `attempts` times.
    fn next_source(&self, attempts: u32) -> usize {
        self.eligible_from(rotate(attempts, self.sources.len()))
    }

    /// The failure to report for a range whose attempt budget ran out.
    ///
    /// A transfer with mirrors has spent that budget across its whole source list, so it reports the
    /// failover it exhausted; one with a single source had nowhere to go, so the stall of the one
    /// source it had is still the whole story.
    fn exhausted(&self, attempts: u32) -> FetchError {
        let at_bytes = self.durable.load(Ordering::SeqCst);
        if self.sources.len() > 1 {
            FetchError::AllSourcesFailed {
                url: self.primary().clone(),
                sources: self.sources.len(),
                attempts,
                at_bytes,
            }
        } else {
            FetchError::Stalled {
                url: self.primary().clone(),
                at_bytes,
            }
        }
    }

    /// Wait out the backoff for work that has failed `attempts` times, honoring a server-named pause.
    /// `false` means the transfer ended or was cancelled while waiting, so the caller must stop
    /// rather than re-queue.
    async fn backoff(
        &self,
        attempts: u32,
        asked: Option<Duration>,
        cancel: &CancellationToken,
    ) -> bool {
        let delay = self.retry.delay(attempts, asked, &self.jitter);
        tokio::select! {
            biased;
            () = self.done.cancelled() => false,
            waited = sleep_or_cancel(delay, cancel) => waited,
        }
    }

    /// Append a completed interval to the journal, if one is being kept.
    async fn journal_commit(&self, start: u64, end: u64) -> Result<(), FetchError> {
        let mut journal = self.journal.lock().await;
        if let Some(journal) = journal.as_mut() {
            journal
                .commit_interval(start, end)
                .await
                .map_err(|e| FetchError::io(&self.apdl, e))?;
        }
        Ok(())
    }
}

/// Set up and run a segmented transfer, then verify and publish.
#[allow(clippy::too_many_arguments)]
async fn transfer(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    len: u64,
    seg_size: u64,
    verify: Verify,
    etag: Option<Vec<u8>>,
    last_modified: Option<Vec<u8>>,
    progress: Reporter,
    cancel: CancellationToken,
    shared: &Shared,
) -> Result<VerifiedFile, FetchError> {
    let dest = spec.dest();
    let part = download::sidecar(dest, ".part");
    let apdl = download::sidecar(dest, ".apdl");
    let block_verify = verify.blocks.map(|plan| Arc::new(BlockVerify::new(plan)));

    // A fresh transfer records the probe's validators so a later resume can revalidate with `If-Range`.
    let identity = Identity {
        etag,
        last_modified,
        ..download::base_identity(spec, Some(len))
    };

    // Resume: trust the journaled intervals only when the identity matches and the `.part` is fully
    // preallocated (so every covered byte is within the file). The recorded validator becomes this
    // run's `If-Range` so a source that changed since is caught.
    let mut covered = IntervalSet::new();
    let mut if_range = None;
    if spec.resume()
        && let Some(loaded) = journal::load(&apdl)
            .await
            .map_err(|e| FetchError::io(&apdl, e))?
        && loaded.identity.matches(&identity)
        && let Ok(meta) = tokio::fs::metadata(&part).await
        && meta.is_file()
        && meta.len() >= len
    {
        if_range = loaded
            .identity
            .etag
            .clone()
            .or_else(|| loaded.identity.last_modified.clone());
        covered = loaded.intervals;
    }

    preallocate(&part, len).await?;

    let gaps = covered.complement(len);
    let already = covered.covered_len();
    progress.emit(already, Some(len), Phase::Connecting);

    // Block mode always runs the engine, even with no gaps: a resume-complete file still has to have
    // every durable block re-hashed from disk before it can be trusted (the block analogue of the
    // single-connection path re-seeding its whole-file hash on resume).
    if !gaps.is_empty() || block_verify.is_some() {
        let journal = if already > 0 {
            Some(
                Journal::open_append(&apdl)
                    .await
                    .map_err(|e| FetchError::io(&apdl, e))?,
            )
        } else {
            Journal::create(&apdl, &identity)
                .await
                .map_err(|e| FetchError::io(&apdl, e))?
        };

        let mut queue = VecDeque::new();
        for gap in &gaps {
            let mut start = gap.start;
            while start < gap.end {
                let end = (start + seg_size).min(gap.end);
                queue.push_back(Task {
                    range: start..end,
                    source: 0,
                });
                start = end;
            }
        }
        // Block mode needs at least one worker parked and ready even with an empty queue, so a
        // dirty-block re-fetch has somewhere to run.
        let worker_count = if block_verify.is_some() {
            shared.max_connections_per_file.min(queue.len().max(1))
        } else {
            shared.max_connections_per_file.min(queue.len())
        };

        let state = Arc::new(TransferState {
            client: client.clone(),
            sources: spec.sources(),
            part: part.clone(),
            apdl: apdl.clone(),
            len,
            stall_timeout: shared.stall_timeout,
            header_policy: spec.header_policy().cloned(),
            if_range,
            limiter: shared.limiter.clone(),
            scheduler: shared.scheduler.clone(),
            reporter: progress.clone(),
            retry: shared.retry,
            jitter: shared.jitter.clone(),
            queue: Mutex::new(queue),
            notify: Notify::new(),
            progress_notify: Notify::new(),
            durable: AtomicU64::new(already),
            covered: Mutex::new(covered),
            attempts: Mutex::new(HashMap::new()),
            ranges_ignored: Mutex::new(HashSet::new()),
            journal: tokio::sync::Mutex::new(journal),
            verify: block_verify,
            hash_limit: Arc::new(Semaphore::new(hash_concurrency())),
            done: CancellationToken::new(),
            end: Mutex::new(None),
        });

        let aggregate = tokio::spawn(aggregator(state.clone(), progress.clone(), len));
        let verifier = state
            .verify
            .is_some()
            .then(|| tokio::spawn(block_verifier(state.clone(), cancel.clone())));
        let workers: Vec<_> = (0..worker_count)
            .map(|_| tokio::spawn(worker(state.clone(), cancel.clone())))
            .collect();
        for handle in workers {
            let _ = handle.await;
        }
        // All workers have exited; wind the aggregator and verifier down. Workers record the outcome in
        // `end`: `Some(Ok)` on completion, `Some(Err)` on failure. A pure external cancel exits every
        // worker without a finish, so `end` stays `None` - read authoritatively here rather than racing
        // a watcher task against the `done` token.
        state.done.cancel();
        let _ = aggregate.await;
        if let Some(verifier) = verifier {
            let _ = verifier.await;
        }

        match lock(&state.end).take() {
            Some(Ok(())) => {} // completed: fall through to verify + publish
            Some(Err(err)) => return Err(err),
            None => return Err(FetchError::Cancelled), // cancelled before completion; part + journal kept
        }
    }

    verify_and_publish(dest, &part, &apdl, len, verify.digest, &progress).await
}

/// Emit a monotonic download snapshot on every progress tick, so concurrent workers cannot interleave
/// a smaller `bytes_done` after a larger one. A dirty block clears its bytes and drops `durable`, so
/// the snapshot is clamped to a high-water mark: progress never regresses across a block repair.
async fn aggregator(state: Arc<TransferState>, progress: Reporter, len: u64) {
    let mut high = state.durable.load(Ordering::SeqCst);
    loop {
        tokio::select! {
            biased;
            () = state.done.cancelled() => return,
            () = state.progress_notify.notified() => {
                high = high.max(state.durable.load(Ordering::SeqCst));
                progress.emit(high, Some(len), Phase::Downloading);
            }
        }
    }
}

/// The outcome of one segment attempt.
enum SegmentResult {
    /// The segment's range is fully durable.
    Done,
    /// The connection dropped or stalled, or the server refused with a retryable status; the
    /// remaining bytes must be re-fetched after a backoff. `asked` carries a `Retry-After` the
    /// server named, which the policy clamps before honoring.
    Requeue {
        range: Range<u64>,
        asked: Option<Duration>,
    },
    /// The primary returned a `200` where a `206` was expected (the source changed under us).
    SourceChanged,
    /// A mirror returned a `200` where a `206` was expected: it will not serve ranges, so it can
    /// serve neither a segment nor a block repair. Costs the transfer that one source, not the job.
    RangesIgnored { range: Range<u64> },
    /// The transfer is ending (finished or cancelled); stop working.
    Stop,
    /// An unrecoverable failure for the whole job.
    Fatal(FetchError),
}

/// A worker: pull tasks and stream them until the transfer finishes.
async fn worker(state: Arc<TransferState>, cancel: CancellationToken) {
    while let Some(task) = state.pop_or_wait(&cancel).await {
        let source = task.source;
        match stream_segment(&state, task, &cancel).await {
            SegmentResult::Done => {}
            // An empty remainder is a finished segment, not a stuck one: the connection went after the
            // last byte was already durable, so there is nothing left to ask for. It falls through to
            // the completion check below rather than being charged an attempt and a backoff. The
            // charge would land on the *next* segment's budget (the ranges are contiguous, so the
            // remainder starts exactly where that one does) and could fail a transfer whose bytes all
            // arrived.
            SegmentResult::Requeue { range, .. } if range.is_empty() => {}
            SegmentResult::Requeue {
                range: remaining,
                asked,
            } => {
                if !requeue(&state, remaining, asked, &cancel).await {
                    return; // the transfer ended or was cancelled during the backoff
                }
            }
            SegmentResult::RangesIgnored { range } => {
                // The worker that learns a mirror will not serve ranges moves the range on for free:
                // nothing was served and nothing is worth waiting for, and the verdict is recorded
                // once for the whole transfer, so the free moves are capped at one per mirror. A
                // worker that raced to the same verdict finds it already recorded and is charged an
                // attempt like any other failure. Between them, no source can hand out an unbudgeted
                // lap of the work queue.
                if state.mark_ranges_ignored(source) {
                    let moved_to = state.eligible_from(source + 1);
                    state.counters().source_dropped();
                    tracing::warn!(
                        url = %state.sources[source],
                        source,
                        moved_to,
                        offset = range.start,
                        "a mirror answered a ranged request with a whole body; dropping it from the rotation",
                    );
                    state.push_task(Task {
                        source: moved_to,
                        range,
                    });
                } else if !requeue(&state, range, None, &cancel).await {
                    return;
                }
            }
            SegmentResult::SourceChanged => {
                // A changed source restarts clean: drop the stale journal and surface the typed
                // changed-source error so a retry re-downloads from scratch. The stale `If-Range`
                // value rides the event here; the error carries the pair that fits its size budget.
                tracing::warn!(
                    url = %state.primary(),
                    stale_validator = state
                        .if_range
                        .as_deref()
                        .map(|v| String::from_utf8_lossy(v).into_owned()),
                    "the primary answered a conditional range with a whole body; the file changed under the transfer",
                );
                let _ = tokio::fs::remove_file(&state.apdl).await;
                state.finish(Err(FetchError::ServerFileChanged {
                    url: state.primary().clone(),
                    detail: "the primary answered a conditional range with a whole body",
                }));
            }
            SegmentResult::Stop => return,
            SegmentResult::Fatal(err) => state.finish(Err(err)),
        }
        // Whole-file mode finishes when every byte is durable. Block mode finishes only when the
        // verifier confirms every block, so a file whose bytes are all on disk but not yet verified must
        // not end here. Completion is checked on every path, not just `Done`: a stall or drop can flush
        // the file's final bytes and return an empty `Requeue`, which `push_task` drops, so the `Done`
        // arm would never see it. `finish` is first-writer-wins, so a redundant call is harmless.
        if state.verify.is_none() && state.durable.load(Ordering::SeqCst) >= state.len {
            state.finish(Ok(()));
        }
        if state.done.is_cancelled() {
            return;
        }
    }
}

/// Charge a failed range one attempt and put it back on the queue, or fail the transfer once its
/// budget is gone. Returns whether the worker may carry on with its loop: `false` only when the
/// transfer ended or a cancel landed while the range was waiting out its backoff.
///
/// Exhausting the budget records the outcome and returns `true`, leaving the worker's own completion
/// check to notice the transfer has finished, exactly as every other terminal path here does.
async fn requeue(
    state: &TransferState,
    range: Range<u64>,
    asked: Option<Duration>,
    cancel: &CancellationToken,
) -> bool {
    let attempts = state.bump_attempt(range.start);
    if !state.retry.may_retry(attempts) {
        tracing::warn!(
            url = %state.primary(),
            offset = range.start,
            remaining = range.end - range.start,
            attempts,
            "a segment exhausted its attempt budget",
        );
        state.finish(Err(state.exhausted(attempts)));
        return true;
    }
    let (from, to) = state.rotation(attempts);
    state.counters().retry(from, to);
    tracing::debug!(
        url = %state.sources[to],
        offset = range.start,
        remaining = range.end - range.start,
        attempts,
        from,
        to,
        "re-queueing a segment after a backoff",
    );
    if !state.backoff(attempts, asked, cancel).await {
        return false;
    }
    // The re-queued range goes wherever the rotation names, which is the source that just failed for
    // one more try and then each of the others in turn. A dead or silent host therefore costs this
    // range a couple of attempts rather than every one of them, which is the whole point of carrying
    // mirrors: before this, only a block that failed its hash could reach one.
    state.push_task(Task {
        source: state.next_source(attempts),
        range,
    });
    true
}

/// The block verifier: as bytes become durable, hash each newly-complete block off the transfer path
/// and either confirm it or re-queue it for a repair. Finishes the transfer once every block verifies.
async fn block_verifier(state: Arc<TransferState>, cancel: CancellationToken) {
    let Some(verify) = state.verify.clone() else {
        return;
    };
    loop {
        // Claim and dispatch every block whose bytes are now durable. take_ready reads coverage live, so
        // this is process-first: a resume with everything already durable still hashes every loaded
        // block on the first pass.
        for i in verify.take_ready(&state.covered) {
            spawn_hash(state.clone(), verify.clone(), i, cancel.clone());
        }
        tokio::select! {
            biased;
            () = state.done.cancelled() => return,
            () = cancel.cancelled() => return,
            () = verify.notify.notified() => {}
        }
    }
}

/// Hash one claimed block on a blocking worker, then report the verdict. Kept off the transfer path:
/// the block is fully durable and out of the work queue, so this read never races a worker's write.
fn spawn_hash(
    state: Arc<TransferState>,
    verify: Arc<BlockVerify>,
    i: u32,
    cancel: CancellationToken,
) {
    let part = state.part.clone();
    let range = verify.block_range(i);
    let want = verify.expected(i);
    let limit = state.hash_limit.clone();
    tokio::spawn(async move {
        // Bound concurrent hashing so a burst cannot saturate the blocking pool the transfer also
        // uses. The permit is scoped to the hash itself: reporting a verdict does no hashing, and a
        // dirty block's verdict waits out a backoff, so holding it any longer would park the whole
        // verification pipeline behind however long a repair was told to wait.
        let hashed = {
            let Ok(_permit) = limit.acquire_owned().await else {
                return; // the semaphore is never closed; this only guards a shutdown race
            };
            tokio::task::spawn_blocking(move || block::hash_block(&part, range)).await
        };
        match hashed {
            Ok(Ok(got)) if got == want => on_verified(&state, &verify, i, &cancel),
            Ok(Ok(_)) => on_dirty(&state, &verify, i, &cancel).await,
            Ok(Err(e)) => state.finish(Err(FetchError::io(&state.part, e))),
            Err(_) => state.finish(Err(FetchError::io(
                &state.part,
                std::io::Error::other("block hash worker panicked"),
            ))),
        }
    });
}

/// A block passed: mark it verified and, if it was the last, finish the transfer. A late result landing
/// after an external cancel must not publish a cancelled job, so the completion is gated on `!cancel`.
fn on_verified(state: &TransferState, verify: &BlockVerify, i: u32, cancel: &CancellationToken) {
    if state.done.is_cancelled() {
        return;
    }
    let verified = verify.mark_verified(i);
    if verified == verify.count() && !cancel.is_cancelled() {
        state.finish(Ok(()));
    }
}

/// A block failed its hash: spend one retry and either re-fetch just that block (clearing its bytes so
/// `durable` and `covered` stay consistent) or, once the budget is gone, fail the whole file.
async fn on_dirty(state: &TransferState, verify: &BlockVerify, i: u32, cancel: &CancellationToken) {
    if state.done.is_cancelled() || cancel.is_cancelled() {
        return;
    }
    let range = verify.block_range(i);
    let attempts = verify.bump_attempt(i);
    if !state.retry.may_retry(attempts) {
        tracing::warn!(
            block = i,
            offset = range.start,
            attempts,
            "a block failed its hash on every attempt; failing the file",
        );
        // Drop the journal so a retry restarts clean rather than trusting the bad interval.
        let _ = tokio::fs::remove_file(&state.apdl).await;
        state.finish(Err(FetchError::BlockVerifyFailed {
            block: i,
            offset: range.start,
            attempts,
        }));
        return;
    }
    // Clear the block's coverage and reset it to pending atomically, so a concurrent verifier pass
    // cannot re-dispatch it against stale coverage before its bytes are re-fetched. This happens
    // before the backoff, not after: leaving the bad bytes marked durable for the length of a wait
    // would let a verifier pass re-dispatch the block against coverage it has already failed.
    verify.clear_and_reset(i, &state.covered, range.clone());
    state
        .durable
        .fetch_sub(range.end - range.start, Ordering::SeqCst);
    let (from, source) = state.rotation(attempts);
    state.counters().block_refetched();
    state.counters().retry(from, source);
    tracing::warn!(
        block = i,
        offset = range.start,
        len = range.end - range.start,
        attempts,
        from,
        source,
        "a block failed its hash; clearing it for a re-fetch",
    );
    if !state.backoff(attempts, None, cancel).await {
        return; // the transfer ended or was cancelled during the backoff
    }
    state.push_task(Task { range, source });
}

/// Stream one segment's range into the preallocated `.part` at its offset, journaling each durable
/// batch. Holds one global connection slot for the segment's lifetime.
async fn stream_segment(
    state: &TransferState,
    task: Task,
    cancel: &CancellationToken,
) -> SegmentResult {
    let range = task.range;
    let url = &state.sources[task.source];
    let _conn = state.scheduler.acquire_connection().await;
    let mut file = match open_segment_file(&state.part, range.start).await {
        Ok(file) => file,
        Err(err) => return SegmentResult::Fatal(err),
    };

    let mut request = apply_headers(state.client.get(url.clone()), state.header_policy.as_ref())
        .header(RANGE, format!("bytes={}-{}", range.start, range.end - 1));
    // On resume, revalidate the source against the recorded validator: a changed source answers a
    // conditional range with a full `200`, which we treat as a changed source. Only the primary carries
    // `If-Range`; a mirror's validators may differ, and the block hash is the real check anyway.
    if task.source == 0
        && let Some(value) = &state.if_range
        && let Ok(header) = reqwest::header::HeaderValue::from_bytes(value)
    {
        request = request.header(IF_RANGE, header);
    }
    let resp = tokio::select! {
        biased;
        () = cancel.cancelled() => return SegmentResult::Stop,
        () = state.done.cancelled() => return SegmentResult::Stop,
        sent = download::send_bounded(request, state.stall_timeout) => match sent {
            Ok(Ok(resp)) => resp,
            // A source that takes the request and sends no headers has not delivered these bytes, so
            // the segment goes back on the queue and rotates, exactly as a dropped body does. Without
            // this the worker parked here forever, holding its connection slot, and the transfer's
            // stall detection never saw it because no body had begun.
            Err(_elapsed) => {
                state.counters().stall();
                tracing::warn!(
                    url = %url,
                    offset = range.start,
                    timeout_ms = state.stall_timeout.as_millis(),
                    "a segment got no response headers within the deadline",
                );
                return SegmentResult::Requeue { range, asked: None };
            }
            // A connect error is transient: re-queue the whole range. A redirect this client's policy
            // refused is not - the source keeps pointing where it points - so it fails the transfer
            // rather than spending the range's whole attempt budget on the same refusal.
            Ok(Err(e)) if classify_send_error(&e) == Class::Fatal => {
                return SegmentResult::Fatal(download::connect_error(url, e));
            }
            Ok(Err(_)) => return SegmentResult::Requeue { range, asked: None },
        },
    };
    match resp.status().as_u16() {
        // A whole body where a range was asked for means different things by source. From the primary
        // it is the source changing under a conditional range, which is only ever answered by
        // restarting clean. From a mirror it says one thing and no more: this mirror will not serve
        // ranges. That is a verdict on the mirror, so it costs the transfer that source and nothing
        // else. Reading it as a changed source instead would let any range-ignoring mirror fail a
        // download the primary was serving perfectly well.
        200 if task.source == 0 => return SegmentResult::SourceChanged,
        200 => return SegmentResult::RangesIgnored { range },
        206 => {}
        // A throttling or overload answer is not a verdict on the request, so the range goes back on
        // the queue and waits instead of failing the job.
        status if classify_status(status) == Class::Retryable => {
            return SegmentResult::Requeue {
                range,
                asked: retry_after(resp.headers()),
            };
        }
        status => {
            return SegmentResult::Fatal(FetchError::Http {
                status,
                url: url.clone(),
            });
        }
    }
    match content_range(&resp) {
        // The range must start where we asked, and the server's total (when concrete) must match the
        // caller's declared length - the same cross-check the single-connection path also enforces.
        Some((first, total)) => {
            if first != range.start {
                return SegmentResult::Fatal(FetchError::Http {
                    status: 206,
                    url: url.clone(),
                });
            }
            if let Some(total) = total
                && total != state.len
            {
                return SegmentResult::Fatal(FetchError::LengthMismatch {
                    expected: state.len,
                    got: total,
                });
            }
        }
        None => {
            return SegmentResult::Fatal(FetchError::Http {
                status: 206,
                url: url.clone(),
            });
        }
    }

    let mut stream = Box::pin(resp.bytes_stream());
    let mut batch: Vec<u8> = Vec::with_capacity(BATCH as usize);
    let mut committed = range.start;
    loop {
        let item = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                let _ = commit_batch(&mut file, &mut batch, &mut committed, state).await;
                return SegmentResult::Stop;
            }
            () = state.done.cancelled() => {
                let _ = commit_batch(&mut file, &mut batch, &mut committed, state).await;
                return SegmentResult::Stop;
            }
            () = tokio::time::sleep(state.stall_timeout) => {
                // Inactivity past the stall timeout: flush what is durable and re-queue the rest.
                if let Err(err) = commit_batch(&mut file, &mut batch, &mut committed, state).await {
                    return SegmentResult::Fatal(err);
                }
                state.counters().stall();
                tracing::warn!(
                    url = %url,
                    offset = range.start,
                    gained = committed - range.start,
                    timeout_ms = state.stall_timeout.as_millis(),
                    "a segment's body went quiet past the inactivity timeout",
                );
                return SegmentResult::Requeue {
                    range: committed..range.end,
                    asked: None,
                };
            }
            item = stream.next() => item,
        };
        let Some(chunk) = item else { break };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => {
                let _ = commit_batch(&mut file, &mut batch, &mut committed, state).await;
                return SegmentResult::Requeue {
                    range: committed..range.end,
                    asked: None,
                };
            }
        };
        let bytes: &[u8] = chunk.as_ref();
        state.limiter.acquire(bytes.len() as u64).await;
        // Clamp to the requested range. All Square Enix input is hostile: a server may answer a closed
        // range with an over-long body, and writing past range.end would overwrite a neighboring block
        // that is already verified and never re-hashed. Keep only up to range.end, commit, and finish
        // the segment; the extra bytes are dropped with the dropped stream.
        let room = range.end.saturating_sub(committed + batch.len() as u64);
        if bytes.len() as u64 > room {
            batch.extend_from_slice(&bytes[..room as usize]);
            if let Err(err) = commit_batch(&mut file, &mut batch, &mut committed, state).await {
                return SegmentResult::Fatal(err);
            }
            break;
        }
        batch.extend_from_slice(bytes);
        if batch.len() as u64 >= BATCH
            && let Err(err) = commit_batch(&mut file, &mut batch, &mut committed, state).await
        {
            return SegmentResult::Fatal(err);
        }
    }
    if let Err(err) = commit_batch(&mut file, &mut batch, &mut committed, state).await {
        return SegmentResult::Fatal(err);
    }
    // A short 206 (fewer bytes than the range) leaves a gap; re-queue the remainder.
    if committed < range.end {
        return SegmentResult::Requeue {
            range: committed..range.end,
            asked: None,
        };
    }
    SegmentResult::Done
}

/// Flush the buffered batch: write it, `fsync` the data, journal the now-durable interval, advance the
/// durable counter, and tick progress. A no-op on an empty batch.
async fn commit_batch(
    file: &mut tokio::fs::File,
    batch: &mut Vec<u8>,
    committed: &mut u64,
    state: &TransferState,
) -> Result<(), FetchError> {
    if batch.is_empty() {
        return Ok(());
    }
    file.write_all(batch)
        .await
        .map_err(|e| FetchError::io(&state.part, e))?;
    file.sync_data()
        .await
        .map_err(|e| FetchError::io(&state.part, e))?;
    let bytes = batch.len() as u64;
    let end = *committed + bytes;
    state.journal_commit(*committed, end).await?;
    state.durable.fetch_add(bytes, Ordering::SeqCst);
    lock(&state.covered).insert(*committed, end);
    state.progress_notify.notify_one();
    // Nudge the block verifier: this batch may have completed a whole block.
    if let Some(verify) = &state.verify {
        verify.notify.notify_one();
    }
    *committed = end;
    batch.clear();
    Ok(())
}

/// Open the preallocated `.part` for writing and position at `at` (segments write sequentially from
/// their start, so no further seeks are needed).
async fn open_segment_file(part: &Path, at: u64) -> Result<tokio::fs::File, FetchError> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(part)
        .await
        .map_err(|e| FetchError::io(part, e))?;
    file.seek(SeekFrom::Start(at))
        .await
        .map_err(|e| FetchError::io(part, e))?;
    Ok(file)
}

/// The first byte and total of a `Content-Range: bytes first-last/total` header, through the one
/// shared parser.
fn content_range(resp: &reqwest::Response) -> Option<(u64, Option<u64>)> {
    let value = resp.headers().get(CONTENT_RANGE)?.to_str().ok()?;
    crate::multipart::parse_content_range(value).map(|(first, _last, total)| (first, total))
}

/// Re-hash the completed `.part` (for a whole-file validator), then publish it: durable, atomic
/// rename, parent-dir `fsync`, journal removed.
async fn verify_and_publish(
    dest: &Path,
    part: &Path,
    apdl: &Path,
    len: u64,
    pin: Option<DigestPin>,
    progress: &Reporter,
) -> Result<VerifiedFile, FetchError> {
    if let Some(pin) = pin {
        progress.emit(len, Some(len), Phase::Verifying);
        let expected = pin.bytes();
        let got = download::hash_file(part, pin).await?;
        if got != expected {
            // Drop the journal so a retry restarts clean rather than re-assembling the same bad bytes.
            let _ = tokio::fs::remove_file(apdl).await;
            return Err(FetchError::FileVerifyFailed {
                expected: download::hex(&expected),
                got: download::hex(&got),
            });
        }
    }
    // No single write handle survived the workers, so re-open to make the assembled data durable. Also
    // truncate to `len`: preallocation extends but never shrinks, so a `.part` left longer by a prior
    // interrupted download to the same destination would otherwise keep a stale, unverified tail past
    // `len` (block mode does no whole-file hash to catch it). Every byte in [0, len) is verified.
    if let Ok(file) = tokio::fs::OpenOptions::new().write(true).open(part).await {
        file.set_len(len)
            .await
            .map_err(|e| FetchError::io(part, e))?;
        let _ = file.sync_all().await;
    }
    download::publish(dest, part, apdl, len, Some(len), progress).await
}
