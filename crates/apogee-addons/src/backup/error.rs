//! Config backup failures.

use std::path::PathBuf;

use thiserror::Error;

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
}
