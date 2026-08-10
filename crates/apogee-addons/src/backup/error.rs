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
    /// A filesystem step failed.
    // Both directions, because this arm covers creating and renaming and removing as well as reading:
    // a capture reads, a restore writes, and pruning deletes.
    #[error("{path:?} could not be read or written")]
    #[non_exhaustive]
    Io {
        /// What it was working on.
        path: PathBuf,
        /// The failure the filesystem raised.
        #[source]
        source: std::io::Error,
    },
    /// A selected source tree does not exist.
    #[error("source tree {path:?} is missing")]
    MissingRoot {
        /// The directory that was expected.
        path: PathBuf,
    },
    /// An include rule selected nothing, which is a selection that no longer describes the tree.
    #[error("{rule} matched nothing under {root:?}")]
    #[non_exhaustive]
    RuleMatchedNothing {
        /// The rule, as written.
        rule: String,
        /// The tree it was applied to.
        root: PathBuf,
    },
    /// One selection lists the same rule twice.
    #[error("{rule} is listed twice for {root:?}")]
    #[non_exhaustive]
    DuplicateRule {
        /// The rule, as written.
        rule: String,
        /// The tree it was listed against.
        root: PathBuf,
    },
    /// Two roots resolve to one directory, so its files would be captured twice.
    #[error("{path:?} is the same directory as {first:?}")]
    #[non_exhaustive]
    DuplicateRoot {
        /// The root that repeats one already selected.
        path: PathBuf,
        /// The root it collides with.
        first: PathBuf,
    },
    /// A name that cannot be recorded, since an archive entry name is text.
    #[error("{path:?} has a name that is not valid UTF-8")]
    #[non_exhaustive]
    NonUtf8Name {
        /// The offending path.
        path: PathBuf,
    },
    /// A tree that nests deeper than a config tree does.
    #[error("{path:?} nests deeper than {limit} directories")]
    #[non_exhaustive]
    TooDeep {
        /// Where the walk gave up.
        path: PathBuf,
        /// The depth cap.
        limit: usize,
    },
    /// Every selected root held nothing, so there is no archive to write.
    #[error("no source tree held anything to back up")]
    NothingSelected,
    /// One entry could not be written into the archive.
    #[error("writing archive entry {entry} failed")]
    #[non_exhaustive]
    Archive {
        /// The entry name, as it would appear in the archive.
        entry: String,
        /// What the archive writer raised.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The record that describes an archive could not be read or written.
    #[error("the archive record could not be read or written")]
    #[non_exhaustive]
    Manifest {
        /// What the serializer or the filesystem raised.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A file that is not one of this launcher's archives.
    ///
    /// The record inside is what proves an archive is ours, never the filename.
    #[error("{path:?} is not one of our archives")]
    #[non_exhaustive]
    NotAnArchive {
        /// The file that was opened.
        path: PathBuf,
    },
    /// An archive written by a newer build, whose format this one does not read.
    #[error("{path:?} is format {found}, and this build reads up to {supported}")]
    #[non_exhaustive]
    UnsupportedFormat {
        /// The archive.
        path: PathBuf,
        /// The format version it declares.
        found: u32,
        /// The highest version this build reads.
        supported: u32,
    },
    /// More entries than an archive may hold.
    #[error("{found} entries selected, more than the {limit} an archive may hold")]
    #[non_exhaustive]
    TooManyEntries {
        /// How many the selection came to.
        found: usize,
        /// The cap.
        limit: usize,
    },
    /// More bytes than an archive may hold.
    #[error("{found} bytes selected, more than the {limit} an archive may hold")]
    #[non_exhaustive]
    TooLarge {
        /// How many bytes the selection came to.
        found: u64,
        /// The cap.
        limit: u64,
    },
    /// An entry name an archive may carry and a restore may not write.
    ///
    /// Refusing aborts the restore rather than skipping the entry: a skip would report success on an
    /// incomplete tree.
    #[error("archive entry {entry} refused: {reason}")]
    #[non_exhaustive]
    RejectedEntry {
        /// The entry name, as the archive spells it.
        entry: String,
        /// Which rule it broke.
        reason: RejectReason,
    },
    /// An entry whose bytes are not the bytes the archive recorded for it.
    #[error("archive entry {entry} does not match the hash the archive recorded for it")]
    #[non_exhaustive]
    ContentMismatch {
        /// The entry name, as the archive spells it.
        entry: String,
    },
    /// A root was handed over with no include rules, so it would have walked its tree and admitted
    /// none of it.
    #[error("{path:?} has no include rules, so it would cover nothing")]
    #[non_exhaustive]
    NoIncludeRules {
        /// The root that was handed over.
        path: PathBuf,
    },
    /// The operation is not one this platform can do. Restore opens every target against a directory
    /// descriptor and refuses symlinks along the way, which is unix-only by construction: there is no
    /// safe fallback to offer, so it is a refusal rather than a missing function.
    #[error("{what} is not supported on this platform")]
    #[non_exhaustive]
    Unsupported {
        /// What is not supported.
        what: &'static str,
    },
    /// The token fired, so the work stopped where it was.
    ///
    /// Its own variant rather than an I/O failure: a caller counts what went wrong to decide whether
    /// it did what was asked, and a run somebody stopped on purpose has nothing to count. Nothing
    /// half-written survives either way, so there is no partial state to describe.
    #[error("cancelled")]
    Cancelled,
}
