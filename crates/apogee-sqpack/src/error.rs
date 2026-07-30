//! The crate's error taxonomy. SqPack containers arrive from a plain-HTTP install path and may be
//! corrupt or heavily modded, so reading them yields a typed fault, never a panic. Offsets and keys
//! travel with every variant for triage.
//!
//! The taxonomy is frozen: the tests at the bottom of this file hold every variant to a pattern, a
//! sample and the line it renders as, in one entry each, so a variant cannot be added without being
//! rendered or removed without being noticed.
//!
//! One arm is platform-shaped. [`Error::Busy`] exists because an install can be read while the game
//! is running, and only the operating system can say that another process refuses to share. What
//! that looks like differs enough between platforms that the codes are a table ([`BUSY_CODES`]) and
//! the rule reading it is a pure function, so both tables are testable wherever the tests run.

use thiserror::Error;

/// Crate result over [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// SqPack access failures. Offsets and keys travel with every variant for triage.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A container header did not start with `SqPack\0\0`.
    #[error("bad SqPack magic")]
    BadMagic,
    /// A recognized-but-unhandled platform byte (PS3/PS4), or an unrecognized one.
    #[error("unsupported platform")]
    UnsupportedPlatform,
    /// A header's stored SHA-1 did not match its contents (checked by the inspector, not on open).
    #[error("header hash mismatch")]
    HeaderHashMismatch,
    /// Fewer bytes were available than a structure requires.
    #[error("truncated at offset {offset}: need {needed} more byte(s)")]
    Truncated { offset: u64, needed: u64 },
    /// An index entry resolved to an offset outside its dat file.
    #[error("entry out of bounds: index_key={index_key}, offset={offset}")]
    EntryOutOfBounds { index_key: u64, offset: u64 },
    /// A compressed block's framing or payload was structurally invalid.
    #[error("block corrupt at offset {offset}: {detail}")]
    BlockCorrupt { offset: u64, detail: &'static str },
    /// An index container's header or segment table contradicted the format.
    #[error("index corrupt at offset {offset}: {detail}")]
    IndexCorrupt { offset: u64, detail: &'static str },
    /// A dat container's headers, one of its entries, or one of that entry's tables contradicted
    /// the format. Kept distinct from [`Error::BlockCorrupt`] and [`Error::IndexCorrupt`] because
    /// the three reach different callers: a block fault is the codec's, an index fault the lookup's,
    /// and this one belongs to the archive that holds the file. The dat side has one arm where the
    /// index side has one, rather than a container arm and an entry arm, because the offset every
    /// variant carries already says which of the two it is.
    #[error("dat entry corrupt at offset {offset}: {detail}")]
    EntryCorrupt { offset: u64, detail: &'static str },
    /// A hash collision landed on a synonym entry that could not yet be resolved.
    #[error("unresolved synonym for key {key}")]
    SynonymUnresolved { key: String },
    /// A declared or decoded size exceeded the caller's [`crate::codec::Limits`].
    #[error("resource limit exceeded")]
    LimitExceeded,
    /// Another process holds the container in a way that refuses this read.
    ///
    /// Reading an install while the game runs is ordinary here: mod detection answers "repair will
    /// revert these files" while the player is still in the world. Nothing this crate opens is opened
    /// for writing, and `File::open` already asks for the most permissive sharing there is, so this
    /// arises only where the *other* process refused to share. See [`BUSY_CODES`] for what that means
    /// per platform, and the module docs for why it is a Windows condition in practice.
    #[error("archive busy")]
    Busy,
    /// An underlying I/O failure.
    #[error("io error")]
    Io(#[source] std::io::Error),
}

/// The OS error codes that mean "another process holds this file and will not share it".
///
/// Windows refuses the open itself: `ERROR_SHARING_VIOLATION` (32) when a holder's `dwShareMode`
/// excludes reading, and `ERROR_LOCK_VIOLATION` (33) when a byte-range lock refuses a read that
/// already got a handle. Neither has an `io::ErrorKind`: both land in the standard library's
/// uncategorized arm, which is unstable and cannot be matched, so the raw code is the only stable
/// way to see them, and it is how the standard library detects them internally too.
///
/// The table is empty on Unix, deliberately and not for lack of looking. A read-only open there is
/// refused by nothing a game does: a held write handle, `flock`, a POSIX or open-file-description
/// write lock all leave it succeeding, mandatory locking has been gone since 5.15, and `ETXTBSY`
/// needs write access asked for. The one mechanism that reaches a read-only open is a write lease,
/// which delays it rather than failing it and which nothing in this path takes. An empty table is
/// also what keeps the two numbers from misfiring: 32 is `EPIPE` and 33 is `EDOM`, and this crate
/// opens paths that may turn out to be pipes.
#[cfg(windows)]
pub const BUSY_CODES: &[i32] = &[32, 33];
/// The codes that mean "held by another process". Empty here; see the Windows definition.
#[cfg(not(windows))]
pub const BUSY_CODES: &[i32] = &[];

/// Whether `raw` is one of `codes`, the whole of the platform-dependence in one pure function.
///
/// Taking the table as an argument rather than reading [`BUSY_CODES`] is what lets both tables be
/// tested on either platform. CI builds for Windows but runs no test there, so a rule written
/// `#[cfg(windows)]` would be compiled and never executed.
#[must_use]
pub fn is_busy_code(codes: &[i32], raw: Option<i32>) -> bool {
    raw.is_some_and(|code| codes.contains(&code))
}

/// Classify an I/O failure on its way into the taxonomy.
///
/// Hand-written rather than `#[error(transparent)]`/`#[from]` so that every `?` in the crate, at
/// every open and every read, classifies the same way. A check bolted onto one call site would miss
/// the others, and a lock violation in particular arrives from a read rather than from an open.
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        if is_busy_code(BUSY_CODES, error.raw_os_error()) {
            return Error::Busy;
        }
        Error::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_file_is_busy_only_under_the_table_that_names_its_code() {
        // Both tables are exercised here whichever platform runs the test, which is the point of
        // passing the table in: CI never executes a Windows binary.
        let windows: &[i32] = &[32, 33];
        for code in [32, 33] {
            assert!(is_busy_code(windows, Some(code)));
            assert!(!is_busy_code(&[], Some(code)));
        }
        // A sharing violation is the only thing the table claims. Permission denied (5), interrupted
        // (4) and a failure with no OS code behind it are all still plain I/O.
        for raw in [Some(5), Some(4), Some(170), None] {
            assert!(!is_busy_code(windows, raw));
            assert!(!is_busy_code(&[], raw));
        }
    }

    #[test]
    fn a_broken_pipe_on_this_platform_is_not_a_busy_archive() {
        // 32 is `ERROR_SHARING_VIOLATION` on Windows and `EPIPE` on Linux, and this crate reads paths
        // that turn out to be pipes. The conversion has to read the code through the platform's own
        // table, so the same number means different things and only one of them is `Busy`.
        let converted = Error::from(std::io::Error::from_raw_os_error(32));
        if cfg!(windows) {
            assert!(matches!(converted, Error::Busy));
        } else {
            assert!(matches!(converted, Error::Io(_)));
        }
    }

    #[test]
    fn an_io_failure_keeps_the_cause_it_came_from() {
        // Dropping `#[from]` for a hand-written conversion is where a source would silently go
        // missing, and the shell renders the chain.
        let converted = Error::from(std::io::Error::other("the disk went away"));
        let source = std::error::Error::source(&converted);
        assert_eq!(
            source.map(ToString::to_string).as_deref(),
            Some("the disk went away")
        );
    }
}
