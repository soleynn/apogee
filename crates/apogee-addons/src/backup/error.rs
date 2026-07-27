//! Config backup failures.

use std::path::PathBuf;

use thiserror::Error;

use super::confine::RejectReason;

/// Config backup failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BackupError {
    #[error("{path:?} could not be read")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("source tree {path:?} is missing")]
    MissingRoot { path: PathBuf },
    #[error("{rule} matched nothing under {root:?}")]
    RuleMatchedNothing { rule: String, root: PathBuf },
    #[error("{rule} is listed twice for {root:?}")]
    DuplicateRule { rule: String, root: PathBuf },
    #[error("{path:?} is the same directory as {first:?}")]
    DuplicateRoot { path: PathBuf, first: PathBuf },
    #[error("{path:?} has a name that is not valid UTF-8")]
    NonUtf8Name { path: PathBuf },
    #[error("{path:?} nests deeper than {limit} directories")]
    TooDeep { path: PathBuf, limit: usize },
    #[error("no source tree held anything to back up")]
    NothingSelected,
    #[error("writing archive entry {entry} failed")]
    Archive {
        entry: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("the archive record could not be read or written")]
    Manifest {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("{path:?} is not one of our archives")]
    NotAnArchive { path: PathBuf },
    #[error("{path:?} is format {found}, and this build reads up to {supported}")]
    UnsupportedFormat {
        path: PathBuf,
        found: u32,
        supported: u32,
    },
    #[error("{found} entries selected, more than the {limit} an archive may hold")]
    TooManyEntries { found: usize, limit: usize },
    #[error("{found} bytes selected, more than the {limit} an archive may hold")]
    TooLarge { found: u64, limit: u64 },
    #[error("archive entry {entry} refused: {reason}")]
    RejectedEntry { entry: String, reason: RejectReason },
    #[error("archive entry {entry} does not match the hash the archive recorded for it")]
    ContentMismatch { entry: String },
}
