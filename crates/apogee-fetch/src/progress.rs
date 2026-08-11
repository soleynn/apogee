//! Download progress events, and the running tally of what the transfer recovered from to produce
//! them.
//!
//! The engines report two different things through one channel. [`Progress::bytes_done`] answers
//! "how far along", which a consumer reads from every event; [`Progress::recoveries`] answers "how
//! hard was it", which most consumers ignore until something looks wrong. Both ride the same event
//! because the second is only meaningful beside the first: forty retries over 140 GiB is a healthy
//! link, and forty over 4 MiB is not.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tokio::sync::mpsc;

/// A snapshot of a download's progress, relayed over a channel the caller owns. A plain, clockless
/// data struct: the consumer derives rate and ETA from successive `bytes_done`, so the same event
/// serves the shell, the CLI, and tests identically.
///
/// `#[non_exhaustive]`: consumers read these fields but never construct the struct (it is minted by
/// the engine and relayed verbatim, e.g. through `apogee-runtime`'s event enum), so a future field
/// can be added without breaking them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Progress {
    /// Bytes durably written and hashed so far. Monotonic within a run.
    pub bytes_done: u64,
    /// The total expected length once known (the caller's `expected_len`, else the server's
    /// advertised length), or `None` when the source declares neither.
    pub total: Option<u64>,
    /// Which stage the download has reached.
    pub phase: Phase,
    /// What the transfer has recovered from on its way to this point.
    pub recoveries: Recoveries,
}

/// The stage a download has reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Phase {
    /// Opening the connection and reading response headers.
    Connecting,
    /// Streaming the body to disk.
    Downloading,
    /// Hashing the finished file for the whole-file validator.
    Verifying,
    /// The file is verified and published to its destination.
    Complete,
}

/// What a transfer has recovered from, counted from the moment it started.
///
/// Every one of these is a situation the engine handles and carries on from, so none of them
/// reaches the caller as a [`FetchError`](crate::FetchError). That is the point: a transfer that
/// retried forty times and one that never retried both end in the same `Ok`, and without a tally
/// the two are indistinguishable from outside the process. The crate's error taxonomy carries this
/// same triage data (which block, which offset, how many attempts) but only ever builds it at the
/// point of failure, which is exactly the case where nobody needed telling.
///
/// Running totals for one call, never reset and never decremented, so a consumer can difference
/// successive events the way it already does for `bytes_done`. A resumed transfer starts from zero:
/// these count this process's work, not the file's history.
///
/// Exhaustive, unlike the [`Progress`] carrying it. The event stays open because a consumer only
/// ever reads it, but a consumer's *tests* have to build one of these to check what its own shell
/// renders, and a `#[non_exhaustive]` bag of counters cannot be built at all from outside. The cost
/// is that a seventh counter breaks those tests rather than being absorbed silently, which is the
/// direction worth failing in: the field above this one is `phase`, which every relay in this
/// workspace quietly drops, and nothing anywhere went red about it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Recoveries {
    /// Attempts charged to the retry budget after a failed one, over every unit of work the
    /// transfer has: a segment, a block re-fetch, the capability probe, and a single-connection
    /// body. Counted when the retry is about to happen, so the attempt that exhausts the budget and
    /// fails the transfer is not one of these.
    pub retries: u32,
    /// The subset of `retries` that moved work to a source other than the one that just failed it.
    /// Always `0` for a transfer with no mirrors, which is every transfer this launcher currently
    /// makes.
    pub rotations: u32,
    /// Times a source went quiet past the stall timeout, on either the response-header deadline or
    /// the body inactivity timer. A stall costs an attempt, so each of these has a `retries` bump
    /// beside it unless it was the attempt that ran the budget out.
    pub stalls: u32,
    /// Blocks that failed their SHA-1 and were cleared for a targeted re-fetch. Bytes that arrived
    /// corrupt and had to be asked for again, which is the one counter here that says the wire, the
    /// disk, or the source is actually wrong rather than merely slow.
    pub blocks_refetched: u32,
    /// Mirrors dropped from the rotation for answering a ranged request with a whole body. Never
    /// counts the primary: a whole body from the primary is a changed source, not a capability
    /// verdict, and it fails the transfer rather than shrinking its source list.
    pub sources_dropped: u32,
    /// Whether the transfer gave up segmentation for one streaming connection because the primary
    /// ignored the capability probe's range. Costs throughput and nothing else, and is the usual
    /// reason a transfer runs several times slower than the same file did yesterday.
    pub demoted: bool,
}

impl Recoveries {
    /// Whether the transfer has had nothing to recover from. The ordinary case, and the one a
    /// consumer renders by saying nothing at all.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_fetch::Recoveries;
    ///
    /// assert!(Recoveries::default().is_clean());
    /// ```
    #[must_use]
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }
}

/// The live counters behind [`Recoveries`], shared by every worker of one transfer.
///
/// Atomics rather than one lock: the segmented engine bumps these from each connection worker and
/// from the block verifier, which do not otherwise coordinate, and each counter is an independent
/// running total that nothing branches on. `Relaxed` is therefore enough, and a snapshot may pair a
/// rotation one worker has just counted with a stall another has not yet. It is a tally, not a
/// consistent instant, and `bytes_done` beside it is no different.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    retries: AtomicU32,
    rotations: AtomicU32,
    stalls: AtomicU32,
    blocks_refetched: AtomicU32,
    sources_dropped: AtomicU32,
    demoted: AtomicBool,
}

impl Counters {
    /// Charge one retry, and a rotation with it when the next try goes to a different source.
    ///
    /// The two are counted together because rotation is a pure function of the attempt count
    /// (see [`rotate`](crate::retry::rotate)), so there is no rotation that is not also a retry, and
    /// counting them apart would let the pair drift at a site that forgot one.
    pub(crate) fn retry(&self, from: usize, to: usize) {
        self.retries.fetch_add(1, Ordering::Relaxed);
        if from != to {
            self.rotations.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count a source going quiet past the stall timeout.
    pub(crate) fn stall(&self) {
        self.stalls.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a block cleared for re-fetch after failing its SHA-1.
    pub(crate) fn block_refetched(&self) {
        self.blocks_refetched.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a mirror dropped from the rotation for ignoring ranges.
    pub(crate) fn source_dropped(&self) {
        self.sources_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that the transfer demoted to a single connection.
    pub(crate) fn demote(&self) {
        self.demoted.store(true, Ordering::Relaxed);
    }

    /// Read every counter for the event about to be sent.
    pub(crate) fn snapshot(&self) -> Recoveries {
        Recoveries {
            retries: self.retries.load(Ordering::Relaxed),
            rotations: self.rotations.load(Ordering::Relaxed),
            stalls: self.stalls.load(Ordering::Relaxed),
            blocks_refetched: self.blocks_refetched.load(Ordering::Relaxed),
            sources_dropped: self.sources_dropped.load(Ordering::Relaxed),
            demoted: self.demoted.load(Ordering::Relaxed),
        }
    }
}

/// The progress channel and one transfer's counters, carried together.
///
/// Both engines thread this instead of a bare sender, so a [`Progress`] cannot be built without the
/// recoveries that belong on it, and every site that can emit an event can also bump a counter. The
/// sender stays optional: `None` is a caller that wants no progress, and the counters still run
/// under it because they also feed the crate's own tracing.
#[derive(Clone)]
pub(crate) struct Reporter {
    tx: Option<mpsc::UnboundedSender<Progress>>,
    counters: Arc<Counters>,
}

impl Reporter {
    /// A reporter over `tx`, with counters starting at zero.
    pub(crate) fn new(tx: Option<mpsc::UnboundedSender<Progress>>) -> Self {
        Self {
            tx,
            counters: Arc::new(Counters::default()),
        }
    }

    /// This transfer's counters, to bump at a recovery site.
    pub(crate) fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Send one event, stamped with the counters as they stand. A closed or absent channel is
    /// ignored: progress is advisory, and a consumer that stopped listening must not fail a
    /// transfer that is otherwise going fine.
    pub(crate) fn emit(&self, bytes_done: u64, total: Option<u64>, phase: Phase) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Progress {
                bytes_done,
                total,
                phase,
                recoveries: self.counters.snapshot(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transfer_that_recovered_from_nothing_is_clean() {
        let counters = Counters::default();
        assert!(counters.snapshot().is_clean());
    }

    /// Each counter reaches its own field and no other, so a consumer reading one recovery is not
    /// shown another.
    #[test]
    fn every_counter_lands_in_its_own_field() {
        let counters = Counters::default();
        counters.stall();
        counters.block_refetched();
        counters.source_dropped();
        counters.demote();
        let snapshot = counters.snapshot();
        assert_eq!(
            snapshot,
            Recoveries {
                retries: 0,
                rotations: 0,
                stalls: 1,
                blocks_refetched: 1,
                sources_dropped: 1,
                demoted: true,
            }
        );
        assert!(!snapshot.is_clean());
    }

    /// A retry that stays on the same source is not a rotation; one that moves is both.
    #[test]
    fn a_rotation_is_a_retry_that_changed_source() {
        let counters = Counters::default();
        counters.retry(0, 0);
        assert_eq!(counters.snapshot().retries, 1);
        assert_eq!(counters.snapshot().rotations, 0);
        counters.retry(0, 1);
        assert_eq!(counters.snapshot().retries, 2);
        assert_eq!(counters.snapshot().rotations, 1);
    }

    /// The snapshot rides the event, so a consumer reading one `Progress` sees the tally as it
    /// stood when that event was sent rather than a later one.
    #[tokio::test]
    async fn an_event_carries_the_counters_as_they_stood() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let reporter = Reporter::new(Some(tx));
        reporter.emit(0, Some(100), Phase::Connecting);
        reporter.counters().stall();
        reporter.counters().retry(0, 1);
        reporter.emit(50, Some(100), Phase::Downloading);

        let first = rx.recv().await.expect("the first event");
        assert!(first.recoveries.is_clean());
        let second = rx.recv().await.expect("the second event");
        assert_eq!(second.recoveries.stalls, 1);
        assert_eq!(second.recoveries.retries, 1);
        assert_eq!(second.recoveries.rotations, 1);
    }

    /// A caller that wants no progress still gets counters, because the crate's own tracing reads
    /// them whether or not anyone is listening on the channel.
    #[test]
    fn a_reporter_with_no_channel_still_counts() {
        let reporter = Reporter::new(None);
        reporter.counters().stall();
        reporter.emit(0, None, Phase::Connecting);
        assert_eq!(reporter.counters().snapshot().stalls, 1);
    }
}
