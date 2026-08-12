//! The parent-side failure taxonomy.

use std::path::PathBuf;

use crate::proto::{FrameError, WorkerErrorKind};

/// A failure driving a worker.
///
/// Every arm is a value the caller renders and recovers from. A worker that dies mid-request is
/// [`Gone`](Self::Gone), not a signal that reaches this process: nothing here ends the caller.
///
/// Exhaustive, so the one place that maps these onto a caller's own taxonomy has to name every arm
/// and cannot quietly fold a new one into a catch-all.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The worker could not be started, or refused to start.
    #[error("cannot start the elevated worker: {detail}")]
    Spawn {
        /// What went wrong, including anything the launcher printed.
        detail: String,
        /// The underlying failure, when the fault was this process's own.
        #[source]
        source: Option<std::io::Error>,
    },
    /// A frame could not be written, read, encoded, or decoded.
    #[error("worker framing failed")]
    Frame(#[from] FrameError),
    /// The peer sent a well-formed frame that the protocol does not allow here.
    #[error("worker protocol violation: {detail}")]
    Protocol {
        /// What was expected and what arrived.
        detail: String,
    },
    /// The peer closed or died without answering the request in flight.
    #[error("the elevated worker exited without answering")]
    Gone,
    /// The worker answered with a typed failure.
    #[error("elevated worker failed: {kind:?}: {detail}")]
    Worker {
        /// The failure class.
        kind: WorkerErrorKind,
        /// The file the failure named, when it named one.
        failed_file: Option<PathBuf>,
        /// The rendered underlying error.
        detail: String,
    },
    /// The request was abandoned on the caller's cancellation token.
    #[error("cancelled")]
    Cancelled,
}

/// A worker result.
pub type Result<T> = std::result::Result<T, Error>;
