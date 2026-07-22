//! The aggregated patch-progress event stream.

use crate::Repo;

/// A progress frame from an install, relayed onto one stream from fetch (download) and zipatch
/// (apply). Clockless like the underlying frames: a consumer derives rate/ETA from successive
/// `bytes_done`. `index` is the patch's position in the SE-ordered set. `#[non_exhaustive]` so
/// repair phases can be added later without a break.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PatchProgress {
    /// A patch's bytes are being fetched (relayed from `apogee_fetch::Progress`).
    Downloading {
        repo: Repo,
        index: u32,
        bytes_done: u64,
        total: Option<u64>,
    },
    /// A patch is being applied to disk in strict list order (relayed from
    /// `apogee_zipatch::ApplyProgress`).
    Applying {
        repo: Repo,
        index: u32,
        bytes_done: u64,
        total: Option<u64>,
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
