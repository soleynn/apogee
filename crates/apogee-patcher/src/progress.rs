//! The aggregated patch-progress event stream.

use apogee_fetch::Recoveries;

use crate::Repo;

/// A progress frame from an install, relayed onto one stream from fetch (download) and zipatch
/// (apply). Clockless like the underlying frames: a consumer derives rate from successive
/// `bytes_done`, and an ETA only for the phase that carries a total (`Downloading`). `index` is the
/// patch's position in the SE-ordered set.
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
        repo: Repo,
        index: u32,
        bytes_done: u64,
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
        repo: Repo,
        index: u32,
        bytes_done: u64,
    },
    /// A patch finished applying cleanly and its `.ver` advanced to `version`.
    Applied {
        repo: Repo,
        index: u32,
        version: String,
    },
    /// A repo is being verified against its block index (the CRC sweep), on repair attempt `attempt`
    /// (0 for the initial full pass, then once per re-fetch round).
    Verifying { repo: Repo, attempt: u32 },
    /// A repair pass pulled `bytes` of broken ranges for `repo` this attempt.
    Refetching {
        repo: Repo,
        attempt: u32,
        bytes: u64,
    },
    /// Stray files under `repo` are being moved to the recycler (`count` in this batch).
    Quarantining { repo: Repo, count: usize },
    /// A repo verified clean after repair and its `.ver` advanced to `version`.
    Repaired { repo: Repo, version: String },
}
