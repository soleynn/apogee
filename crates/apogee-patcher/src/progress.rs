//! The aggregated patch-progress event stream.

use apogee_fetch::Recoveries;

use crate::Repo;

/// A progress frame from an install or a repair, all relayed onto one stream. `Downloading` and
/// `Applying` are relayed from `apogee_fetch::Progress` and `apogee_zipatch::ApplyProgress`; the
/// repair phases (`Verifying` through `Repaired`) are this crate's own, since neither lower crate
/// knows about reattempts or quarantine. Clockless like the underlying frames: a consumer derives rate
/// from successive `bytes_done`, and an ETA only for the phase that carries a total (`Downloading`).
/// `index` is the patch's position in the SE-ordered set.
///
/// Deliberately exhaustive, like [`Recoveries`](apogee_fetch::Recoveries) and for the same reason: a
/// renderer that matches every variant is what keeps a future phase from rotting unrendered, and
/// `#[non_exhaustive]` would forbid exactly that match. It carried the attribute to leave room for
/// the repair phases; those have landed, and what the attribute leaves behind is a `_` arm in the
/// renderer that would print a new phase as the word "progress" and fail nothing. A phase nobody can
/// read is not a phase, so a new variant breaks that build instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchProgress {
    /// A patch's bytes are being fetched (relayed from `apogee_fetch::Progress`).
    Downloading {
        /// Which repo the patch belongs to.
        repo: Repo,
        /// The patch's position in the ordered set.
        index: u32,
        /// Bytes transferred so far.
        bytes_done: u64,
        /// The transfer's total size, when known.
        total: Option<u64>,
        /// What the transfer has recovered from to get this far, relayed unchanged. Carried rather
        /// than flattened away because none of it reaches a caller any other way: every recovery it
        /// counts ends in a download that succeeded.
        recoveries: Recoveries,
    },
    /// A patch is being applied to disk in strict list order (relayed from
    /// `apogee_zipatch::ApplyProgress`). Carries no total, unlike `Downloading`: apply progress is
    /// monotonic bytes with no known end, since nothing in the patch format declares how many bytes
    /// reach disk.
    Applying {
        /// Which repo the patch belongs to.
        repo: Repo,
        /// The patch's position in the ordered set.
        index: u32,
        /// Bytes applied so far.
        bytes_done: u64,
    },
    /// A patch finished applying cleanly and its `.ver` advanced to `version`.
    Applied {
        /// Which repo the patch belongs to.
        repo: Repo,
        /// The patch's position in the ordered set.
        index: u32,
        /// The bare version now on disk.
        version: String,
    },
    /// A repo is being verified against its block index (the initial full CRC sweep, before the
    /// reattempt loop). `attempt` is always 0: a later pass re-verifies only the parts an earlier one
    /// left broken, and that refine step carries no frame of its own.
    Verifying {
        /// Which repo is being verified.
        repo: Repo,
        /// Always 0; carried for symmetry with `Refetching`'s attempt counter.
        attempt: u32,
    },
    /// A repair pass pulled `bytes` of broken ranges for `repo` this attempt.
    Refetching {
        /// Which repo the bytes were pulled for.
        repo: Repo,
        /// The repair pass this refetch belongs to.
        attempt: u32,
        /// Bytes pulled over HTTP this attempt.
        bytes: u64,
    },
    /// Stray files under `repo` are being moved to the recycler (`count` in this batch).
    Quarantining {
        /// Which repo the strays were found under.
        repo: Repo,
        /// How many strays are in this batch.
        count: usize,
    },
    /// A repo verified clean after repair and its `.ver` advanced to `version`.
    Repaired {
        /// Which repo was healed.
        repo: Repo,
        /// The bare version now on disk.
        version: String,
    },
}
