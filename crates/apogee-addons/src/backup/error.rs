//! Config backup failures: one taxonomy for capture, restore, and retention alike.

use std::path::PathBuf;

use thiserror::Error;

use super::confine::RejectReason;

/// Config backup failures.
///
/// # Examples
///
/// ```
/// use apogee_addons::backup::BackupError;
///
/// assert_eq!(
///     BackupError::NothingSelected.to_string(),
///     "no source tree held anything to back up"
/// );
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BackupError {
    // Both directions, because this arm covers creating and renaming and removing as well as reading:
    // a capture reads, a restore writes, and pruning deletes.
    #[error("{path:?} could not be read or written")]
    #[non_exhaustive]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("source tree {path:?} is missing")]
    MissingRoot { path: PathBuf },
    #[error("{rule} matched nothing under {root:?}")]
    #[non_exhaustive]
    RuleMatchedNothing { rule: String, root: PathBuf },
    #[error("{rule} is listed twice for {root:?}")]
    #[non_exhaustive]
    DuplicateRule { rule: String, root: PathBuf },
    #[error("{path:?} is the same directory as {first:?}")]
    #[non_exhaustive]
    DuplicateRoot { path: PathBuf, first: PathBuf },
    #[error("{path:?} has a name that is not valid UTF-8")]
    #[non_exhaustive]
    NonUtf8Name { path: PathBuf },
    #[error("{path:?} nests deeper than {limit} directories")]
    #[non_exhaustive]
    TooDeep { path: PathBuf, limit: usize },
    #[error("no source tree held anything to back up")]
    NothingSelected,
    #[error("writing archive entry {entry} failed")]
    #[non_exhaustive]
    Archive {
        entry: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("the archive record could not be read or written")]
    #[non_exhaustive]
    Manifest {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("{path:?} is not one of our archives")]
    #[non_exhaustive]
    NotAnArchive { path: PathBuf },
    #[error("{path:?} is format {found}, and this build reads up to {supported}")]
    #[non_exhaustive]
    UnsupportedFormat {
        path: PathBuf,
        found: u32,
        supported: u32,
    },
    #[error("{found} entries selected, more than the {limit} an archive may hold")]
    #[non_exhaustive]
    TooManyEntries { found: usize, limit: usize },
    #[error("{found} bytes selected, more than the {limit} an archive may hold")]
    #[non_exhaustive]
    TooLarge { found: u64, limit: u64 },
    #[error("archive entry {entry} refused: {reason}")]
    #[non_exhaustive]
    RejectedEntry { entry: String, reason: RejectReason },
    #[error("archive entry {entry} does not match the hash the archive recorded for it")]
    #[non_exhaustive]
    ContentMismatch { entry: String },
    /// A root was handed over with no include rules, so it would have walked its tree and admitted
    /// none of it.
    #[error("{path:?} has no include rules, so it would cover nothing")]
    #[non_exhaustive]
    NoIncludeRules { path: PathBuf },
    /// The operation is not one this platform can do. Restore opens every target against a directory
    /// descriptor and refuses symlinks along the way, which is unix-only by construction: there is no
    /// safe fallback to offer, so it is a refusal rather than a missing function.
    #[error("{what} is not supported on this platform")]
    #[non_exhaustive]
    Unsupported { what: &'static str },
    /// The token fired, so the work stopped where it was.
    ///
    /// Its own variant rather than an I/O failure: a caller counts what went wrong to decide whether
    /// it did what was asked, and a run somebody stopped on purpose has nothing to count. Nothing
    /// half-written survives either way, so there is no partial state to describe.
    #[error("cancelled")]
    Cancelled,
}
