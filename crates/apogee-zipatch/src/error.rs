//! The crate's error taxonomy. Patches arrive over plain HTTP and are treated as hostile: parsing
//! yields a typed fault, never a panic, and every fault raised while reading a patch carries the
//! offset it was read at, so a patch-day failure reads as "chunk at offset 0x… has unknown command
//! 'Z'" instead of a guess.
//!
//! The taxonomy is frozen: the test at the bottom of this file holds every variant of [`Error`],
//! [`Op`] and [`Limit`] to a pattern and a rendered line, so adding one is a deliberate act and the
//! messages are as much a contract as the fields.

use std::path::PathBuf;

use thiserror::Error;

/// Crate result over [`enum@Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// The I/O operation in flight when an [`Error::Io`] occurred.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Op {
    /// Opening a file.
    Open,
    /// Reading from a file or stream.
    Read,
    /// Writing to a file.
    Write,
    /// Setting a file's length.
    Truncate,
    /// Deleting a file.
    Remove,
    /// Creating a directory.
    MakeDir,
}

/// A bounded resource, for [`Error::LimitExceeded`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Limit {
    /// A declared chunk payload length exceeded the parser's cap.
    ChunkSize,
    /// The whole patch declared more chunks than the parser accepts.
    ChunkCount,
    /// A single zero-fill span (an `A` command's delete-tail, or a `D`/`E` empty-block region) ran
    /// past the dat-scale cap.
    FileSize,
    /// A confined path nested deeper than the cap.
    PathDepth,
    /// A compressed block declared a decompressed size past the decode cap.
    BlockSize,
    /// An `.apzi` index body decompressed to more than the decode cap.
    IndexSize,
}

/// ZiPatch parse/apply failures. A fault raised while reading a patch or an index carries the offset
/// it was read at, for triage.
///
/// Three variants deliberately carry none. [`Io`](Error::Io) carries the target path and the
/// operation instead, which is what a filesystem fault is about. [`PathEscape`](Error::PathEscape)
/// carries the offending path, and [`LimitExceeded`](Error::LimitExceeded) the bound and the value:
/// both are raised from places that are not reading the stream (a confinement check handed a string,
/// a sink asked to zero a span), so an offset field would be a zero at most sites, and a zero that
/// means "unknown" is the guess the rest of the taxonomy exists to avoid.
///
/// # The seam constraint
///
/// Two crates with semver commitments reach into this enum, so parts of it are already load-bearing
/// outside the crate and hold until every one of them takes a major together:
///
/// - `apogee-fetch`'s `HttpRangeSource` constructs [`Io`](Error::Io) (with [`Op::Read`]) and
///   [`Corrupt`](Error::Corrupt) by literal, as the [`RangeSource`](crate::RangeSource) impl's only
///   way to report a transport fault.
/// - `apogee-patcher`'s staging sink constructs [`Io`](Error::Io) (with [`Op::Write`]),
///   [`Corrupt`](Error::Corrupt), [`PathEscape`](Error::PathEscape) and
///   [`Unsupported`](Error::Unsupported) by literal, from its [`RepairSink`](crate::RepairSink) impl.
/// - `apogee-patcher` and `apogee-elevate` both *match* [`Cancelled`](Error::Cancelled) by name to
///   turn an aborted apply into their own cancellation, which is the only variant either reads
///   rather than wrapping whole.
///
/// So: sealing any of those five variants, changing their fields, or removing the [`Op::Read`] or
/// [`Op::Write`] row is a breaking change for a crate that is already at 1.0.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O fault, tagged with the operation in flight and the target path when known.
    #[error("io error during {during:?}")]
    Io {
        /// The underlying I/O fault.
        #[source]
        source: std::io::Error,
        /// The file the operation was on, when known.
        target: Option<PathBuf>,
        /// The operation in flight.
        during: Op,
    },
    /// The stream did not begin with the ZiPatch magic.
    #[error("bad patch magic")]
    BadMagic,
    /// A chunk's four-character type is outside the known set.
    #[error("unknown chunk {fourcc:?} at offset {offset}")]
    UnknownChunk {
        /// The unrecognized four-character type.
        fourcc: [u8; 4],
        /// The chunk's absolute file offset.
        offset: u64,
    },
    /// A `SQPK` sub-command byte is outside the known set.
    #[error("unknown command {cmd:#x} at offset {offset}")]
    UnknownCommand {
        /// The unrecognized command byte.
        cmd: u8,
        /// The command's absolute file offset.
        offset: u64,
    },
    /// A chunk's stored CRC32 disagrees with the one computed over its bytes.
    #[error("chunk crc mismatch at offset {offset}: stored {stored}, computed {computed}")]
    ChunkCrcMismatch {
        /// The chunk's absolute file offset.
        offset: u64,
        /// The CRC32 the chunk claims.
        stored: u32,
        /// The CRC32 actually computed.
        computed: u32,
    },
    /// The stream ended before a declared field or chunk finished.
    #[error("truncated at offset {offset}: needed {needed} more byte(s)")]
    Truncated {
        /// The absolute offset the read ran off the end at.
        offset: u64,
        /// How many more bytes the field or chunk needed.
        needed: u64,
    },
    /// A patch-supplied path failed confinement: absolute, containing `..`, naming a drive, or empty.
    #[error("path escape: {raw}")]
    PathEscape {
        /// The offending path, as the patch supplied it.
        raw: String,
    },
    /// A bounded resource's declared value exceeds its cap.
    #[error("limit exceeded: {what:?} value {value} exceeds max {max}")]
    LimitExceeded {
        /// Which resource was bounded.
        what: Limit,
        /// The value that exceeded the cap.
        value: u64,
        /// The cap.
        max: u64,
    },
    /// A structural fault with no more specific variant: a value the format does not allow at all.
    #[error("corrupt at offset {offset}: {detail}")]
    Corrupt {
        /// The absolute file offset the fault was found at.
        offset: u64,
        /// What was wrong, as a short fixed string.
        detail: &'static str,
    },
    /// A structurally valid input this crate does not implement, e.g. a non-Win32 apply target.
    #[error("unsupported: {what}")]
    Unsupported {
        /// What is unsupported, as a short fixed string.
        what: &'static str,
    },
    /// [`ApplyOptions::cancel`](crate::ApplyOptions::cancel) was set between commands.
    #[error("apply cancelled")]
    Cancelled,
    /// An `.apzi` stream did not begin with the index magic.
    #[error("bad index magic")]
    BadIndexMagic,
    /// An `.apzi` stream declared a format version this crate does not read.
    #[error("unsupported index version {version}")]
    UnsupportedIndexVersion {
        /// The declared version.
        version: u16,
    },
}

impl Error {
    /// An I/O fault with no specific target path, tagged with the operation in flight. The single
    /// home for the wrapper every module used to re-declare.
    pub(crate) fn io(source: std::io::Error, during: Op) -> Self {
        Error::Io {
            source,
            target: None,
            during,
        }
    }

    /// Rebase a shared-codec block-decode failure onto the patch file. The codec reports offsets
    /// relative to the block it was handed, but this crate's contract is patch-file-absolute, so add
    /// the block's own offset (`block_off`) back in. `declared`/`limit` supply the numbers a
    /// field-less codec `LimitExceeded` cannot carry itself.
    pub(crate) fn from_block(
        source: apogee_sqpack::Error,
        block_off: u64,
        declared: u32,
        limit: u32,
    ) -> Self {
        use apogee_sqpack::Error as Codec;
        match source {
            Codec::BlockCorrupt { offset, detail } => Error::Corrupt {
                offset: block_off + offset,
                detail,
            },
            Codec::Truncated { offset, needed } => Error::Truncated {
                offset: block_off + offset,
                needed,
            },
            Codec::LimitExceeded => Error::LimitExceeded {
                what: Limit::BlockSize,
                value: u64::from(declared),
                max: u64::from(limit),
            },
            Codec::Io(source) => Error::Io {
                source,
                target: None,
                during: Op::Write,
            },
            _ => Error::Corrupt {
                offset: block_off,
                detail: "block decode failed",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Freeze a taxonomy: every variant as a pattern, a value built from it, and the line it renders
    /// as, in one entry.
    ///
    /// The generated `match` has no wildcard arm, so a variant added to the enum stops this
    /// compiling until it gains an entry, and an entry is a pattern *and* a sample *and* an expected
    /// string. Written instead as a match beside a table, the pair would fail open: the compiler
    /// would force the arm, and the same edit could forget the table, leaving a variant named and
    /// never rendered. Each sample is also checked against its own pattern, so an entry cannot be
    /// filed under one variant while building another.
    ///
    /// What it pins is the rendering, because that is what a patch-day shell prints and what a
    /// `PatchError` chain carries upward. The offsets in the messages are the whole point of the
    /// taxonomy, so they are pinned as text, not just as fields. `render` is a parameter because
    /// [`Error`] renders through `Display` while [`Op`] and [`Limit`] reach a message through
    /// `Debug`, inside one of `Error`'s own format strings.
    macro_rules! frozen {
        ($test:ident, $ty:ty, $render:expr, {
            $( $pat:pat => ($sample:expr, $expected:expr $(,)?) ),+ $(,)?
        }) => {
            #[test]
            fn $test() {
                #[allow(dead_code)]
                fn every_variant_has_an_entry(value: &$ty) {
                    match value { $( $pat => () ),+ }
                }
                let render: fn(&$ty) -> String = $render;
                $({
                    let sample: $ty = $sample;
                    // The pattern is an argument, never the format string: it contains braces.
                    assert!(
                        matches!(sample, $pat),
                        "the sample filed under {} builds a different variant",
                        stringify!($pat),
                    );
                    assert_eq!(render(&sample), $expected, "{}", stringify!($pat));
                })+
            }
        };
    }

    frozen!(every_error_renders_as_recorded, Error, |e| e.to_string(), {
        Error::Io { .. } => (
            Error::io(std::io::Error::other("nope"), Op::Open),
            "io error during Open",
        ),
        Error::BadMagic => (Error::BadMagic, "bad patch magic"),
        Error::UnknownChunk { .. } => (
            Error::UnknownChunk { fourcc: *b"ZZZZ", offset: 4096 },
            "unknown chunk [90, 90, 90, 90] at offset 4096",
        ),
        Error::UnknownCommand { .. } => (
            Error::UnknownCommand { cmd: b'Z', offset: 24 },
            "unknown command 0x5a at offset 24",
        ),
        Error::ChunkCrcMismatch { .. } => (
            Error::ChunkCrcMismatch { offset: 16, stored: 1, computed: 2 },
            "chunk crc mismatch at offset 16: stored 1, computed 2",
        ),
        Error::Truncated { .. } => (
            Error::Truncated { offset: 2048, needed: 16 },
            "truncated at offset 2048: needed 16 more byte(s)",
        ),
        Error::PathEscape { .. } => (
            Error::PathEscape { raw: "../etc/passwd".to_owned() },
            "path escape: ../etc/passwd",
        ),
        Error::LimitExceeded { .. } => (
            Error::LimitExceeded { what: Limit::ChunkSize, value: 4096, max: 16 },
            "limit exceeded: ChunkSize value 4096 exceeds max 16",
        ),
        Error::Corrupt { .. } => (
            Error::Corrupt { offset: 128, detail: "unknown target platform" },
            "corrupt at offset 128: unknown target platform",
        ),
        Error::Unsupported { .. } => (
            Error::Unsupported { what: "non-Win32 target platform" },
            "unsupported: non-Win32 target platform",
        ),
        Error::Cancelled => (Error::Cancelled, "apply cancelled"),
        Error::BadIndexMagic => (Error::BadIndexMagic, "bad index magic"),
        Error::UnsupportedIndexVersion { .. } => (
            Error::UnsupportedIndexVersion { version: 2 },
            "unsupported index version 2",
        ),
    });

    // `Op` and `Limit` render inside `Error`'s messages through `{:?}`, so their names are part of
    // the frozen text and a rename would change a message without touching this file otherwise.
    frozen!(every_op_renders_as_recorded, Op, |op| format!("{op:?}"), {
        Op::Open => (Op::Open, "Open"),
        Op::Read => (Op::Read, "Read"),
        Op::Write => (Op::Write, "Write"),
        Op::Truncate => (Op::Truncate, "Truncate"),
        Op::Remove => (Op::Remove, "Remove"),
        Op::MakeDir => (Op::MakeDir, "MakeDir"),
    });

    frozen!(every_limit_renders_as_recorded, Limit, |l| format!("{l:?}"), {
        Limit::ChunkSize => (Limit::ChunkSize, "ChunkSize"),
        Limit::ChunkCount => (Limit::ChunkCount, "ChunkCount"),
        Limit::FileSize => (Limit::FileSize, "FileSize"),
        Limit::PathDepth => (Limit::PathDepth, "PathDepth"),
        Limit::BlockSize => (Limit::BlockSize, "BlockSize"),
        Limit::IndexSize => (Limit::IndexSize, "IndexSize"),
    });

    /// The type crosses a rayon sweep's thread boundaries and is stored in boxed chains above this
    /// crate. Nothing else pins it: a variant boxing a non-`Send` source would be caught at the first
    /// caller instead of here.
    const _: fn() = || {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<Error>();
    };

    /// The offending source stays reachable through the chain rather than being flattened into the
    /// message, which is what lets a caller print "io error during Read: permission denied".
    #[test]
    fn an_io_fault_keeps_its_source_in_the_chain() {
        let err = Error::io(std::io::Error::other("disk went away"), Op::Read);
        let source = std::error::Error::source(&err).expect("an Io error sources its cause");
        assert_eq!(source.to_string(), "disk went away");
    }
}
