//! What a structural check found, where it found it, and how badly it bears on using the install.
//!
//! One [`Defect`] variant per rule, with the location travelling beside it in a [`Site`] rather than
//! inside it: that is what lets one ordering rule and one renderer cover the whole taxonomy. Every
//! field is an integer, a digest, a small enum or a `&'static str`, so a [`Finding`] is `Copy` and
//! allocates nothing, and the per-container budget bounds what a wrecked container costs to report. It
//! bounds the report and nothing else: what a sweep holds while producing one is the containers it has
//! parsed, which is [`crate::index::IndexLimits`] times the archives in flight.
//!
//! [`Severity`] and [`Scope`] are derived from the defect rather than stored beside it, so neither can
//! drift: severity says how much a fault bears on playing the game (a mod tool's coherent rewrite is
//! [`Severity::Altered`], not corruption), and scope says what putting it right costs.

use std::fmt;
use std::path::PathBuf;

use crate::archive::{ArchiveId, PLATFORM_TAG};
use crate::container::COMMON_HEADER_LEN;
use crate::dat::DATA_UNIT;
use crate::error::Error;
use crate::game::Repo;
use crate::index::IndexKind;
use crate::integrity::{ContainerReport, Totals};

/// The directory every SqPack container of an install sits under.
const SQPACK_DIR: &str = "sqpack";

/// Which file of an archive a finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ContainerId {
    /// The archive as a whole, for a fault that belongs to no single file.
    Archive,
    /// One of the archive's two index containers.
    Index(IndexKind),
    /// The archive's `.dat{n}`.
    Dat(u8),
}

/// Which container a finding is about. Ordering is the report's grouping order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContainerRef {
    /// The repository holding the archive.
    pub repo: Repo,
    /// The archive, as its file names spell it.
    pub archive: ArchiveId,
    /// Which of the archive's files.
    pub file: ContainerId,
}

impl ContainerRef {
    /// A reference to one file of one archive.
    #[must_use]
    pub fn new(repo: Repo, archive: ArchiveId, file: ContainerId) -> Self {
        Self {
            repo,
            archive,
            file,
        }
    }

    /// The same archive, another of its files.
    #[must_use]
    pub fn with_file(self, file: ContainerId) -> Self {
        Self { file, ..self }
    }

    /// The file's name, or `None` for [`ContainerId::Archive`].
    #[must_use]
    pub fn file_name(&self) -> Option<String> {
        match self.file {
            ContainerId::Archive => None,
            ContainerId::Index(kind) => Some(self.archive.index_file_name(kind)),
            ContainerId::Dat(dat) => Some(self.archive.dat_file_name(dat)),
        }
    }

    /// `sqpack/ffxiv/0a0000.win32.index`, relative to the game subtree. For
    /// [`ContainerId::Archive`] the archive's stem, `sqpack/ffxiv/0a0000`.
    #[must_use]
    pub fn relative_path(&self) -> PathBuf {
        let leaf = self.file_name().unwrap_or_else(|| self.archive.stem());
        PathBuf::from(SQPACK_DIR)
            .join(self.repo.dir_name())
            .join(leaf)
    }

    /// The container a game-subtree-relative path names, or `None` for a path that names none.
    ///
    /// The inverse of [`ContainerRef::relative_path`], and here rather than in whatever crate needs
    /// it because the layout is this crate's to know: anything holding a list of file paths (a patch
    /// chain's targets, a verification of them) has to get from those to containers, and a second
    /// hand-rolled parse elsewhere is a second thing to be wrong.
    ///
    /// Strict on purpose. Only a name this crate would itself build is accepted, so an uppercase
    /// stem, a `.bck`, a `movie/…` or a path outside `sqpack/` answers `None` rather than being
    /// bent into some container's identity.
    #[must_use]
    pub fn from_relative_path(path: &std::path::Path) -> Option<Self> {
        let mut parts = path.components();
        let sqpack = parts.next()?.as_os_str().to_str()?;
        if sqpack != SQPACK_DIR {
            return None;
        }
        let repo = Repo::from_dir_name(parts.next()?.as_os_str().to_str()?)?;
        let name = parts.next()?.as_os_str().to_str()?;
        if parts.next().is_some() {
            return None;
        }
        let (stem, rest) = name.split_once(&format!(".{PLATFORM_TAG}."))?;
        let archive = ArchiveId::parse_stem(stem).filter(|id| id.stem() == stem)?;
        let file = match rest {
            "index" => ContainerId::Index(IndexKind::Index1),
            "index2" => ContainerId::Index(IndexKind::Index2),
            _ => ContainerId::Dat(rest.strip_prefix("dat")?.parse().ok()?),
        };
        Some(Self::new(repo, archive, file))
    }
}

/// Where a fault is. `offset` is always a byte position inside `container`; a byte position in some
/// other file (a dat offset an index named) travels in the defect's own fields instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Site {
    /// The container the offset is measured in.
    pub container: ContainerRef,
    /// The byte position, when the check knows one.
    pub offset: Option<u64>,
    /// The index key that named the byte, when a lookup led there.
    pub key: Option<u64>,
}

/// Where a fault is and what is wrong there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// Where the fault is.
    pub site: Site,
    /// What is wrong there.
    pub defect: Defect,
}

impl Finding {
    /// How badly the fault bears on using the install.
    #[must_use]
    pub fn severity(&self) -> Severity {
        self.defect.severity()
    }

    /// What putting the fault right costs.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.defect.scope()
    }

    /// The defect's stable machine key.
    #[must_use]
    pub fn slug(&self) -> &'static str {
        self.defect.slug()
    }
}

/// One self-contained line: the container's path, the byte position and key the check reached, and
/// what is wrong there.
impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.site.container.relative_path().display())?;
        if let Some(offset) = self.site.offset {
            write!(f, " +{offset:#08x}")?;
        }
        if let Some(key) = self.site.key {
            write!(f, " key={key:#018x}")?;
        }
        write!(f, ": ")?;
        describe(self.defect, f)
    }
}

/// How badly a fault bears on using the install. The order is the severity order, so `max()` over a
/// report is its worst finding.
///
/// Not `#[non_exhaustive]`: three arms are the whole axis, and a renderer must be able to match it
/// exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The bytes differ from what the container declares about itself, yet everything still resolves.
    /// A dat a mod tool rewrote lands here, which is why this arm exists: the worst mistake available
    /// is telling a modded user their install is corrupt.
    Altered,
    /// Something the game reads is provably wrong.
    Damaged,
    /// The container could not be read at all, so nothing else about it is known.
    Unusable,
}

/// What putting a finding right costs, which is what a targeted repair keys on. Not
/// `#[non_exhaustive]`, for the same reason as [`Severity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// One file inside an archive: re-fetch that entry's bytes.
    File,
    /// One container: the whole `.index`/`.index2`/`.dat` has to be replaced.
    Container,
    /// The archive's files disagree; which of them is wrong is not decided here.
    Archive,
}

/// Why a read produced nothing, folded down from [`crate::Error`] so a defect stays `Copy`, comparable
/// and orderable. The parser's own `detail` travels beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ReadFault {
    /// The container did not start with the SqPack magic.
    Magic,
    /// The container declared a platform this crate does not read.
    Platform,
    /// A structure ran past the end of the bytes.
    Truncated,
    /// An index container contradicted the format.
    IndexCorrupt,
    /// A dat container or one of its entries contradicted the format.
    EntryCorrupt,
    /// A compressed block's framing or payload was invalid.
    BlockCorrupt,
    /// A declared size exceeded the caller's limits.
    LimitExceeded,
    /// The container was locked by a running game.
    Busy,
    /// The container is there and this process may not read it.
    Permission,
    /// The container was gone by the time the read reached it.
    Missing,
    /// The read itself failed.
    Io,
    /// Anything else the reader refused.
    Other,
}

impl ReadFault {
    /// How the fault reads in a rendered line.
    fn label(self) -> &'static str {
        match self {
            ReadFault::Magic => "bad SqPack magic",
            ReadFault::Platform => "unsupported platform",
            ReadFault::Truncated => "truncated",
            ReadFault::IndexCorrupt => "index corrupt",
            ReadFault::EntryCorrupt => "entry corrupt",
            ReadFault::BlockCorrupt => "block corrupt",
            ReadFault::LimitExceeded => "over a caller limit",
            ReadFault::Busy => "archive busy",
            ReadFault::Permission => "permission denied",
            ReadFault::Missing => "not on disk",
            ReadFault::Io => "io error",
            ReadFault::Other => "unreadable",
        }
    }
}

/// Fold a reader error into the fault, the parser's own detail, and the byte position it names.
///
/// Matched arm by arm with no wildcard, even though [`Error`] is `#[non_exhaustive]` and a wildcard
/// would compile: this is the one place the taxonomy narrows, and a new variant folding silently to
/// [`ReadFault::Other`] would reach every report in the crate as "unreadable" with nothing said about
/// why. The compiler asks instead.
pub(crate) fn read_fault(error: &Error) -> (ReadFault, &'static str, Option<u64>) {
    match *error {
        Error::BadMagic => (ReadFault::Magic, "", None),
        Error::UnsupportedPlatform => (ReadFault::Platform, "", None),
        Error::Truncated { offset, .. } => (ReadFault::Truncated, "", Some(offset)),
        Error::IndexCorrupt { offset, detail } => (ReadFault::IndexCorrupt, detail, Some(offset)),
        Error::EntryCorrupt { offset, detail } => (ReadFault::EntryCorrupt, detail, Some(offset)),
        Error::BlockCorrupt { offset, detail } => (ReadFault::BlockCorrupt, detail, Some(offset)),
        Error::EntryOutOfBounds { offset, .. } => (ReadFault::EntryCorrupt, "", Some(offset)),
        Error::LimitExceeded => (ReadFault::LimitExceeded, "", None),
        Error::Busy => (ReadFault::Busy, "", None),
        Error::Io(ref error) => (io_fault(error.kind()), "", None),
        // A lookup fault, not a container one: nothing that opens or parses a container raises it, so
        // it has no fault of its own to fold to. Named rather than left to a wildcard so that stays a
        // decision.
        Error::SynonymUnresolved { .. } => (ReadFault::Other, "", None),
    }
}

/// Which fault an io failure folds to. The kind is all of a `std::io::Error` a `Copy` defect can carry,
/// and it is the difference between a container whose permissions or ownership are wrong, one that went
/// away mid-sweep, and a device that answered with an error: three faults with three different things to
/// do about them. `ErrorKind` is `#[non_exhaustive]`, so everything else stays [`ReadFault::Io`].
fn io_fault(kind: std::io::ErrorKind) -> ReadFault {
    match kind {
        std::io::ErrorKind::PermissionDenied => ReadFault::Permission,
        std::io::ErrorKind::NotFound => ReadFault::Missing,
        _ => ReadFault::Io,
    }
}

/// A header word every container of its kind spells the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum HeaderWord {
    /// The common header's declared length.
    CommonHeaderSize,
    /// The common header's format version.
    CommonVersion,
    /// The index or data header's declared length.
    SecondHeaderSize,
    /// The index or data header's format version.
    SecondVersion,
    /// The data header's word at `0x08`, whose role is not settled and whose value never varies.
    DataUnclassified,
    /// The data header's reserved word at `0x04`.
    DataReserved0,
    /// The data header's reserved word at `0x14`.
    DataReserved1,
    /// The data header's reserved word at `0x1C`.
    DataReserved2,
}

impl HeaderWord {
    /// How the word reads in a rendered line.
    fn label(self) -> &'static str {
        match self {
            HeaderWord::CommonHeaderSize => "the common header's declared size",
            HeaderWord::CommonVersion => "the common header's version",
            HeaderWord::SecondHeaderSize => "the second header's declared size",
            HeaderWord::SecondVersion => "the second header's version",
            HeaderWord::DataUnclassified => "the data header's word at 0x08",
            HeaderWord::DataReserved0 => "the data header's reserved word at 0x04",
            HeaderWord::DataReserved1 => "the data header's reserved word at 0x14",
            HeaderWord::DataReserved2 => "the data header's reserved word at 0x1c",
        }
    }
}

/// Which of a container's two headers a finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum HeaderId {
    /// The `SqPack` common header at `0x000`.
    Common,
    /// The index or data header at `0x400`.
    Second,
}

impl HeaderId {
    /// Where the header starts, and so what its own digest covers from. An index and a dat lay these
    /// out alike: the common header at `0x000` and the form-specific one after it.
    pub(crate) fn starts_at(self) -> usize {
        match self {
            HeaderId::Common => 0,
            HeaderId::Second => COMMON_HEADER_LEN,
        }
    }

    /// How the header reads in a rendered line.
    fn label(self) -> &'static str {
        match self {
            HeaderId::Common => "common",
            HeaderId::Second => "second",
        }
    }
}

/// What is wrong at a [`Site`]. One variant per rule a pristine install was measured to keep, so a
/// pristine install produces none of them.
///
/// Declaration order is the report's tie-break order, which is why related defects sit together. The
/// payload never repeats the site: a defect says what is wrong, the site says where.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Defect {
    // The container could not be read at all.
    /// The container would not open or parse, so nothing else about it is known.
    ContainerUnreadable {
        /// Why the read produced nothing.
        fault: ReadFault,
        /// The reader's own detail, empty when it carried none.
        detail: &'static str,
    },
    /// The archive is missing one of its two index forms.
    IndexFormMissing {
        /// The form that is absent.
        kind: IndexKind,
    },
    /// A data file the archive names is not on disk.
    DataFileMissing {
        /// The `.dat{n}` number.
        dat: u8,
    },

    // A hash the container declares over its own bytes.
    /// A header's SHA-1 over its own leading bytes does not match them.
    HeaderHashMismatch {
        /// Which of the container's two headers.
        header: HeaderId,
        /// The digest the header carries.
        declared: [u8; 20],
        /// The digest its bytes produce.
        computed: [u8; 20],
    },
    /// A segment descriptor's SHA-1 does not match the segment's bytes.
    SegmentHashMismatch {
        /// The 0-based index into the header's segment table.
        segment: u8,
        /// The segment's declared length.
        len: u32,
        /// The digest the descriptor carries.
        declared: [u8; 20],
        /// The digest the segment's bytes produce.
        computed: [u8; 20],
    },
    /// A dat's declared data-region SHA-1 does not match the region's bytes.
    DataRegionHashMismatch {
        /// The region's declared length.
        len: u64,
        /// The digest the data header carries.
        declared: [u8; 20],
        /// The digest the region's bytes produce.
        computed: [u8; 20],
    },
    /// One of the two runs no hash covers is not zero.
    ZeroRegionDirty {
        /// The run's length.
        len: u32,
        /// Absolute offset of the first non-zero byte.
        first_nonzero: u64,
    },

    // The container contradicts the format's header.
    /// A header word every container spells the same is spelled differently here.
    HeaderWord {
        /// Which word.
        word: HeaderWord,
        /// What this container spells.
        declared: u32,
        /// What every measured container spells.
        expected: u32,
    },
    /// The index header declares a form the file name does not.
    IndexKindDisagreesWithName {
        /// The form the header declares.
        declared: IndexKind,
        /// The form the file name spells.
        named: IndexKind,
    },

    // The segment table is not this layout.
    /// A non-empty segment does not start where the previous one ends.
    SegmentsDoNotTile {
        /// The 0-based index into the header's segment table.
        segment: u8,
        /// Where the descriptor says the segment starts.
        declared: u32,
        /// Where the previous segment ends.
        expected: u32,
    },
    /// Bytes sit past the last segment.
    TrailingBytes {
        /// How many.
        len: u64,
    },
    /// A segment's length is not a whole number of its records.
    SegmentRagged {
        /// The 0-based index into the header's segment table.
        segment: u8,
        /// The segment's declared length.
        len: u32,
        /// The length of one of its records.
        record_len: u32,
    },
    /// An `.index2` carries a third segment, which only an `.index` does.
    UnclassifiedSegmentOnSecondForm {
        /// The segment's declared length.
        len: u32,
    },
    /// An `.index2` carries a folder table, which only an `.index` does.
    FolderTableOnSecondForm {
        /// How many rows.
        rows: u32,
    },
    /// An `.index` holding entries carries no folder table.
    FolderTableMissing {
        /// How many entries the container holds.
        entries: u32,
    },

    // The entry table.
    /// An entry's key is below its predecessor's.
    EntryKeysNotAscending {
        /// The predecessor's key.
        previous: u64,
    },
    /// Two entries carry the same key.
    DuplicateEntryKey,
    /// An `.index` entry's reserved word is not zero.
    EntryPadNotZero {
        /// The word as it reads.
        pad: u32,
    },
    /// A collision placeholder's location word carries more than the collision flag.
    CollisionFlagNotBare {
        /// The word as it reads.
        packed: u32,
    },
    /// An entry names a data file the archive does not declare.
    EntryDatOutOfRange {
        /// The `.dat{n}` number the entry names.
        dat: u8,
        /// How many data files the header declares.
        declared: u32,
    },
    /// The index declares a data-file count the directory does not hold.
    DeclaredDatCount {
        /// What the header declares.
        declared: u32,
        /// How many `.dat{n}` are on disk.
        present: u32,
    },

    // The collision table.
    /// The collision table does not end at a terminating record.
    CollisionTableUnterminated {
        /// How many records were walked before the segment ran out.
        records: u32,
    },
    /// A record sits past the collision table's terminator.
    CollisionRecordAfterTerminator,
    /// A collision record's path fills its whole field with no terminator.
    CollisionPathUnterminated,
    /// A collision record's path holds a byte that is not printable ASCII.
    CollisionPathNotAscii {
        /// The byte's index within the path field.
        at: u32,
    },
    /// A collision record's path does not hash to the key it is filed under.
    CollisionPathKeyMismatch {
        /// The key the path does hash to.
        hashes_to: u64,
    },
    /// A collision record's own location word carries the collision flag.
    CollisionRecordIsPlaceholder {
        /// The word as it reads.
        packed: u32,
    },
    /// The conflict indexes under one key are not each of `0..n` exactly once.
    CollisionConflictIndexUnexpected {
        /// The index that is out of range or repeated.
        conflict_index: u32,
        /// How many records the key carries.
        records: u32,
    },
    /// A collision record is filed under a key no entry flags as colliding.
    CollisionRecordWithoutFlaggedEntry,
    /// A collision placeholder's key carries fewer than two collision records.
    FlaggedEntryWithoutRecords {
        /// How many records the key carries.
        records: u32,
    },

    // The folder table.
    /// A folder row's hash is not above its predecessor's.
    FolderRowsNotAscending {
        /// This row's folder hash.
        hash: u32,
        /// The predecessor's.
        previous: u32,
    },
    /// A folder row's reserved word is not zero.
    FolderRowPadNotZero {
        /// The row's folder hash.
        hash: u32,
        /// The word as it reads.
        pad: u32,
    },
    /// The folder rows' runs do not tile the entry segment.
    FolderRowsDoNotTile {
        /// Where the run starts, or where the last run ends.
        declared: u32,
        /// Where the previous run ends, or where the entry segment does.
        expected: u32,
    },
    /// An entry inside a folder row's run carries another folder's hash.
    FolderHashDisagreesWithEntry {
        /// The row's folder hash.
        folder: u32,
        /// The folder hash the entry's key carries.
        entry_folder: u32,
    },

    // The dat container and the archive.
    /// A dat's declared data region does not end at the end of the file.
    DeclaredLength {
        /// `0x800` plus the declared units.
        declared: u64,
        /// The file's length.
        actual: u64,
    },
    /// Only one of the archive's two index forms names a location.
    FormsDisagree {
        /// The form that names it.
        only_in: IndexKind,
        /// The `.dat{n}` it names.
        dat: u8,
        /// The offset within that data file.
        offset: u64,
    },

    // The entries in the dat.
    /// An entry's 20-byte header would not parse.
    EntryHeaderUnreadable {
        /// Why the read produced nothing.
        fault: ReadFault,
        /// The reader's own detail, empty when it carried none.
        detail: &'static str,
    },
    /// An entry declares a content type the format does not define.
    EntryContentTypeUnknown {
        /// The type as it reads.
        declared: u32,
    },
    /// An entry's header length is not a non-zero multiple of the data unit.
    EntryHeaderMisaligned {
        /// The length as it reads.
        header_size: u32,
    },
    /// An entry stores more units than its slot reserves.
    OccupiedExceedsAllocated {
        /// What the entry stores.
        occupied_units: u32,
        /// What its slot reserves.
        allocated_units: u32,
    },
    /// An entry's slot reaches into the next entry's.
    SlotsOverlap {
        /// This slot's length.
        slot_len: u64,
        /// Where the next entry starts.
        next_offset: u64,
    },
    /// An entry sits in the dat's own header rather than in its data region.
    SlotBeforeDataRegion,
    /// An entry's slot ends past the declared data region.
    SlotBeyondDataRegion {
        /// Where the slot ends.
        slot_end: u64,
        /// Where the declared region ends.
        region_end: u64,
    },

    // Unclaimed space and content.
    /// A run of unclaimed space is not tiled exactly by a chain of empty-block headers.
    GapNotEmptyBlockChain {
        /// The run's length.
        len: u64,
        /// How much of it the chain covered.
        covered: u64,
        /// How many regions the walk stepped through.
        regions: u32,
    },
    /// An entry the index named would not decode.
    EntryDecodeFailed {
        /// Why the decode produced nothing.
        fault: ReadFault,
        /// The reader's own detail, empty when it carried none.
        detail: &'static str,
        /// How many bytes came out before it failed.
        produced: u64,
    },
}

/// Every slug [`Defect::slug`] can return, in declaration order, for a renderer that wants the key
/// set up front and for the test that proves the two lists cannot drift apart.
pub const DEFECT_SLUGS: &[&str] = &[
    "container-unreadable",
    "index-form-missing",
    "data-file-missing",
    "header-hash-mismatch",
    "segment-hash-mismatch",
    "data-region-hash-mismatch",
    "zero-region-dirty",
    "header-word",
    "index-kind-disagrees-with-name",
    "segments-do-not-tile",
    "trailing-bytes",
    "segment-ragged",
    "unclassified-segment-on-second-form",
    "folder-table-on-second-form",
    "folder-table-missing",
    "entry-keys-not-ascending",
    "duplicate-entry-key",
    "entry-pad-not-zero",
    "collision-flag-not-bare",
    "entry-dat-out-of-range",
    "declared-dat-count",
    "collision-table-unterminated",
    "collision-record-after-terminator",
    "collision-path-unterminated",
    "collision-path-not-ascii",
    "collision-path-key-mismatch",
    "collision-record-is-placeholder",
    "collision-conflict-index-unexpected",
    "collision-record-without-flagged-entry",
    "flagged-entry-without-records",
    "folder-rows-not-ascending",
    "folder-row-pad-not-zero",
    "folder-rows-do-not-tile",
    "folder-hash-disagrees-with-entry",
    "declared-length",
    "forms-disagree",
    "entry-header-unreadable",
    "entry-content-type-unknown",
    "entry-header-misaligned",
    "occupied-exceeds-allocated",
    "slots-overlap",
    "slot-before-data-region",
    "slot-beyond-data-region",
    "gap-not-empty-block-chain",
    "entry-decode-failed",
];

impl Defect {
    /// A stable kebab-case machine key, so a renderer names every arm without matching a
    /// `#[non_exhaustive]` enum.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Defect::ContainerUnreadable { .. } => "container-unreadable",
            Defect::IndexFormMissing { .. } => "index-form-missing",
            Defect::DataFileMissing { .. } => "data-file-missing",
            Defect::HeaderHashMismatch { .. } => "header-hash-mismatch",
            Defect::SegmentHashMismatch { .. } => "segment-hash-mismatch",
            Defect::DataRegionHashMismatch { .. } => "data-region-hash-mismatch",
            Defect::ZeroRegionDirty { .. } => "zero-region-dirty",
            Defect::HeaderWord { .. } => "header-word",
            Defect::IndexKindDisagreesWithName { .. } => "index-kind-disagrees-with-name",
            Defect::SegmentsDoNotTile { .. } => "segments-do-not-tile",
            Defect::TrailingBytes { .. } => "trailing-bytes",
            Defect::SegmentRagged { .. } => "segment-ragged",
            Defect::UnclassifiedSegmentOnSecondForm { .. } => "unclassified-segment-on-second-form",
            Defect::FolderTableOnSecondForm { .. } => "folder-table-on-second-form",
            Defect::FolderTableMissing { .. } => "folder-table-missing",
            Defect::EntryKeysNotAscending { .. } => "entry-keys-not-ascending",
            Defect::DuplicateEntryKey => "duplicate-entry-key",
            Defect::EntryPadNotZero { .. } => "entry-pad-not-zero",
            Defect::CollisionFlagNotBare { .. } => "collision-flag-not-bare",
            Defect::EntryDatOutOfRange { .. } => "entry-dat-out-of-range",
            Defect::DeclaredDatCount { .. } => "declared-dat-count",
            Defect::CollisionTableUnterminated { .. } => "collision-table-unterminated",
            Defect::CollisionRecordAfterTerminator => "collision-record-after-terminator",
            Defect::CollisionPathUnterminated => "collision-path-unterminated",
            Defect::CollisionPathNotAscii { .. } => "collision-path-not-ascii",
            Defect::CollisionPathKeyMismatch { .. } => "collision-path-key-mismatch",
            Defect::CollisionRecordIsPlaceholder { .. } => "collision-record-is-placeholder",
            Defect::CollisionConflictIndexUnexpected { .. } => {
                "collision-conflict-index-unexpected"
            }
            Defect::CollisionRecordWithoutFlaggedEntry => "collision-record-without-flagged-entry",
            Defect::FlaggedEntryWithoutRecords { .. } => "flagged-entry-without-records",
            Defect::FolderRowsNotAscending { .. } => "folder-rows-not-ascending",
            Defect::FolderRowPadNotZero { .. } => "folder-row-pad-not-zero",
            Defect::FolderRowsDoNotTile { .. } => "folder-rows-do-not-tile",
            Defect::FolderHashDisagreesWithEntry { .. } => "folder-hash-disagrees-with-entry",
            Defect::DeclaredLength { .. } => "declared-length",
            Defect::FormsDisagree { .. } => "forms-disagree",
            Defect::EntryHeaderUnreadable { .. } => "entry-header-unreadable",
            Defect::EntryContentTypeUnknown { .. } => "entry-content-type-unknown",
            Defect::EntryHeaderMisaligned { .. } => "entry-header-misaligned",
            Defect::OccupiedExceedsAllocated { .. } => "occupied-exceeds-allocated",
            Defect::SlotsOverlap { .. } => "slots-overlap",
            Defect::SlotBeforeDataRegion => "slot-before-data-region",
            Defect::SlotBeyondDataRegion { .. } => "slot-beyond-data-region",
            Defect::GapNotEmptyBlockChain { .. } => "gap-not-empty-block-chain",
            Defect::EntryDecodeFailed { .. } => "entry-decode-failed",
        }
    }

    /// How badly the defect bears on using the install.
    #[must_use]
    pub fn severity(self) -> Severity {
        match self {
            Defect::ContainerUnreadable { .. }
            | Defect::IndexFormMissing { .. }
            | Defect::DataFileMissing { .. } => Severity::Unusable,
            // Everything still resolves: the container's own account of its bytes is what differs,
            // which is exactly what a mod tool's coherent rewrite produces.
            Defect::HeaderHashMismatch { .. }
            | Defect::SegmentHashMismatch { .. }
            | Defect::DataRegionHashMismatch { .. }
            | Defect::ZeroRegionDirty { .. }
            | Defect::EntryPadNotZero { .. }
            | Defect::GapNotEmptyBlockChain { .. } => Severity::Altered,
            _ => Severity::Damaged,
        }
    }

    /// What putting the defect right costs.
    #[must_use]
    pub fn scope(self) -> Scope {
        match self {
            Defect::DeclaredDatCount { .. } | Defect::FormsDisagree { .. } => Scope::Archive,
            Defect::EntryHeaderUnreadable { .. }
            | Defect::EntryContentTypeUnknown { .. }
            | Defect::EntryHeaderMisaligned { .. }
            | Defect::OccupiedExceedsAllocated { .. }
            | Defect::SlotsOverlap { .. }
            | Defect::SlotBeforeDataRegion
            | Defect::SlotBeyondDataRegion { .. }
            | Defect::EntryDecodeFailed { .. } => Scope::File,
            _ => Scope::Container,
        }
    }
}

/// The human half of a rendered finding: what is wrong, in the voice [`crate::Error`]'s messages use.
fn describe(defect: Defect, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match defect {
        Defect::ContainerUnreadable { fault, detail } => {
            write!(f, "the container will not parse: {}", fault.label())?;
            write_detail(detail, f)
        }
        Defect::IndexFormMissing { kind } => {
            write!(f, "no .{} beside the archive", kind.extension())
        }
        Defect::DataFileMissing { dat } => write!(f, "dat{dat} is named but not on disk"),
        Defect::HeaderHashMismatch {
            header,
            declared,
            computed,
        } => {
            write!(
                f,
                "the {} header's hash does not cover its bytes: declared ",
                header.label()
            )?;
            write_digest(&declared, f)?;
            write!(f, ", computed ")?;
            write_digest(&computed, f)
        }
        Defect::SegmentHashMismatch {
            segment,
            len,
            declared,
            computed,
        } => {
            write!(f, "segment {segment}'s hash over {len} byte(s): declared ")?;
            write_digest(&declared, f)?;
            write!(f, ", computed ")?;
            write_digest(&computed, f)
        }
        Defect::DataRegionHashMismatch {
            len,
            declared,
            computed,
        } => {
            write!(f, "the data region's hash over {len} byte(s): declared ")?;
            write_digest(&declared, f)?;
            write!(f, ", computed ")?;
            write_digest(&computed, f)
        }
        Defect::ZeroRegionDirty { len, first_nonzero } => write!(
            f,
            "{len} byte(s) no hash covers are not zero, from {first_nonzero:#x}"
        ),
        Defect::HeaderWord {
            word,
            declared,
            expected,
        } => write!(
            f,
            "{} is {declared} where every container spells {expected}",
            word.label()
        ),
        Defect::IndexKindDisagreesWithName { declared, named } => write!(
            f,
            "declared as an .{} in a file named .{}",
            declared.extension(),
            named.extension()
        ),
        Defect::SegmentsDoNotTile {
            segment,
            declared,
            expected,
        } => write!(
            f,
            "segment {segment} starts at {declared:#x} where the previous segment ends at {expected:#x}"
        ),
        Defect::TrailingBytes { len } => write!(f, "{len} byte(s) past the last segment"),
        Defect::SegmentRagged {
            segment,
            len,
            record_len,
        } => write!(
            f,
            "segment {segment} is {len} byte(s), not a whole number of {record_len}-byte records"
        ),
        Defect::UnclassifiedSegmentOnSecondForm { len } => write!(
            f,
            "an .index2 carries {len} byte(s) of third segment, which only an .index has"
        ),
        Defect::FolderTableOnSecondForm { rows } => write!(
            f,
            "an .index2 carries {rows} folder row(s), which only an .index has"
        ),
        Defect::FolderTableMissing { entries } => {
            write!(f, "{entries} entry/entries and no folder table")
        }
        Defect::EntryKeysNotAscending { previous } => {
            write!(f, "the key is below the previous entry's {previous:#018x}")
        }
        Defect::DuplicateEntryKey => write!(f, "two entries carry this key"),
        Defect::EntryPadNotZero { pad } => {
            write!(f, "the entry's reserved word is {pad:#010x}, not zero")
        }
        Defect::CollisionFlagNotBare { packed } => write!(
            f,
            "a collision placeholder's location word is {packed:#010x}, not 1"
        ),
        Defect::EntryDatOutOfRange { dat, declared } => write!(
            f,
            "the entry names dat{dat} where the archive declares {declared} data file(s)"
        ),
        Defect::DeclaredDatCount { declared, present } => write!(
            f,
            "the index declares {declared} data file(s) beside {present} on disk"
        ),
        Defect::CollisionTableUnterminated { records } => write!(
            f,
            "the collision table's {records} record(s) end without a terminator"
        ),
        Defect::CollisionRecordAfterTerminator => {
            write!(f, "a record sits past the collision table's terminator")
        }
        Defect::CollisionPathUnterminated => write!(
            f,
            "the collision record's path fills its field with no terminator"
        ),
        Defect::CollisionPathNotAscii { at } => write!(
            f,
            "byte {at} of the collision record's path is not printable ASCII"
        ),
        Defect::CollisionPathKeyMismatch { hashes_to } => write!(
            f,
            "the collision record's path hashes to {hashes_to:#018x}, not to the key it is filed under"
        ),
        Defect::CollisionRecordIsPlaceholder { packed } => write!(
            f,
            "the collision record's own location word {packed:#010x} is a placeholder"
        ),
        Defect::CollisionConflictIndexUnexpected {
            conflict_index,
            records,
        } => write!(
            f,
            "conflict index {conflict_index} among the {records} record(s) under one key"
        ),
        Defect::CollisionRecordWithoutFlaggedEntry => write!(
            f,
            "no entry flags the key this collision record is filed under"
        ),
        Defect::FlaggedEntryWithoutRecords { records } => write!(
            f,
            "a collision placeholder whose key carries {records} collision record(s)"
        ),
        Defect::FolderRowsNotAscending { hash, previous } => write!(
            f,
            "folder hash {hash:#010x} is not above the previous row's {previous:#010x}"
        ),
        Defect::FolderRowPadNotZero { hash, pad } => write!(
            f,
            "folder {hash:#010x}'s reserved word is {pad:#010x}, not zero"
        ),
        Defect::FolderRowsDoNotTile { declared, expected } => write!(
            f,
            "the folder rows do not tile the entry segment: {declared:#x} where {expected:#x} was expected"
        ),
        Defect::FolderHashDisagreesWithEntry {
            folder,
            entry_folder,
        } => write!(
            f,
            "an entry in folder {folder:#010x}'s run carries folder hash {entry_folder:#010x}"
        ),
        Defect::DeclaredLength { declared, actual } => write!(
            f,
            "the data header declares {declared} byte(s) over a file of {actual}"
        ),
        Defect::FormsDisagree {
            only_in,
            dat,
            offset,
        } => write!(
            f,
            "only the .{} names dat{dat} offset {offset:#x}",
            only_in.extension()
        ),
        Defect::EntryHeaderUnreadable { fault, detail } => {
            write!(f, "the entry header will not parse: {}", fault.label())?;
            write_detail(detail, f)
        }
        Defect::EntryContentTypeUnknown { declared } => {
            write!(f, "content type {declared} is not one the format defines")
        }
        Defect::EntryHeaderMisaligned { header_size } => write!(
            f,
            "the entry header is {header_size} byte(s), not a non-zero multiple of {DATA_UNIT}"
        ),
        Defect::OccupiedExceedsAllocated {
            occupied_units,
            allocated_units,
        } => write!(
            f,
            "the entry stores {occupied_units} unit(s) in a slot reserving {allocated_units}"
        ),
        Defect::SlotsOverlap {
            slot_len,
            next_offset,
        } => write!(
            f,
            "a slot of {slot_len} byte(s) reaches into the entry at {next_offset:#x}"
        ),
        Defect::SlotBeforeDataRegion => {
            write!(f, "the entry sits in the dat's own header")
        }
        Defect::SlotBeyondDataRegion {
            slot_end,
            region_end,
        } => write!(
            f,
            "the entry's slot ends at {slot_end:#x}, past the declared region's {region_end:#x}"
        ),
        Defect::GapNotEmptyBlockChain {
            len,
            covered,
            regions,
        } => write!(
            f,
            "{len} unclaimed byte(s) that {regions} empty-block region(s) cover {covered} of"
        ),
        Defect::EntryDecodeFailed {
            fault,
            detail,
            produced,
        } => {
            write!(
                f,
                "the entry would not decode after {produced} byte(s): {}",
                fault.label()
            )?;
            write_detail(detail, f)
        }
    }
}

/// Append the reader's own detail, which is empty for the faults that carry none.
fn write_detail(detail: &'static str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if detail.is_empty() {
        Ok(())
    } else {
        write!(f, " ({detail})")
    }
}

/// A SHA-1 as the format's own tooling spells it, lowercase hex.
fn write_digest(digest: &[u8; 20], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in digest {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

/// Where a container check files its findings, holding the container they are all about and the
/// budget past which they are counted instead of carried.
///
/// A wrecked container otherwise names one defect per entry, which is megabytes of report nobody
/// reads. Check loops are never cut short by the budget: their work is already bounded by the
/// container's own length, and stopping early would make *which* defects survive depend on where a
/// loop happened to be.
pub(crate) struct Sink {
    container: ContainerRef,
    cap: usize,
    findings: Vec<Finding>,
    suppressed: u64,
}

impl Sink {
    /// A sink for one container, keeping at most `cap` findings.
    pub(crate) fn new(container: ContainerRef, cap: usize) -> Self {
        Self {
            container,
            cap,
            findings: Vec::new(),
            suppressed: 0,
        }
    }

    /// A defect at a byte position.
    pub(crate) fn push_at(&mut self, offset: u64, defect: Defect) {
        self.file(Some(offset), None, defect);
    }

    /// A defect at a byte position an index key led to.
    pub(crate) fn push_keyed(&mut self, offset: u64, key: u64, defect: Defect) {
        self.file(Some(offset), Some(key), defect);
    }

    /// A defect at a byte position the reader may not have named.
    pub(crate) fn push_on(&mut self, offset: Option<u64>, defect: Defect) {
        self.file(offset, None, defect);
    }

    fn file(&mut self, offset: Option<u64>, key: Option<u64>, defect: Defect) {
        if self.findings.len() >= self.cap {
            self.suppressed += 1;
            return;
        }
        self.findings.push(Finding {
            site: Site {
                container: self.container,
                offset,
                key,
            },
            defect,
        });
    }

    /// The container's report: its findings in report order, the totals it accounted for, and whether
    /// the budget filled.
    pub(crate) fn finish(mut self, mut totals: Totals) -> ContainerReport {
        self.findings.sort_unstable();
        totals.defects_suppressed += self.suppressed;
        ContainerReport {
            findings: self.findings,
            totals,
            truncated: self.suppressed > 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of every variant, in declaration order. The compiler makes [`Defect::slug`]'s match
    /// exhaustive; this list plus [`DEFECT_SLUGS`] is what makes a new variant impossible to land
    /// without naming it in both.
    fn every_defect() -> Vec<Defect> {
        vec![
            Defect::ContainerUnreadable {
                fault: ReadFault::Magic,
                detail: "",
            },
            Defect::IndexFormMissing {
                kind: IndexKind::Index2,
            },
            Defect::DataFileMissing { dat: 1 },
            Defect::HeaderHashMismatch {
                header: HeaderId::Common,
                declared: [0; 20],
                computed: [1; 20],
            },
            Defect::SegmentHashMismatch {
                segment: 0,
                len: 16,
                declared: [0; 20],
                computed: [1; 20],
            },
            Defect::DataRegionHashMismatch {
                len: 128,
                declared: [0; 20],
                computed: [1; 20],
            },
            Defect::ZeroRegionDirty {
                len: 44,
                first_nonzero: 0x3D4,
            },
            Defect::HeaderWord {
                word: HeaderWord::CommonHeaderSize,
                declared: 0x800,
                expected: 0x400,
            },
            Defect::IndexKindDisagreesWithName {
                declared: IndexKind::Index2,
                named: IndexKind::Index1,
            },
            Defect::SegmentsDoNotTile {
                segment: 1,
                declared: 0x900,
                expected: 0x810,
            },
            Defect::TrailingBytes { len: 16 },
            Defect::SegmentRagged {
                segment: 2,
                len: 20,
                record_len: 16,
            },
            Defect::UnclassifiedSegmentOnSecondForm { len: 16 },
            Defect::FolderTableOnSecondForm { rows: 1 },
            Defect::FolderTableMissing { entries: 3 },
            Defect::EntryKeysNotAscending { previous: 9 },
            Defect::DuplicateEntryKey,
            Defect::EntryPadNotZero { pad: 7 },
            Defect::CollisionFlagNotBare { packed: 3 },
            Defect::EntryDatOutOfRange {
                dat: 5,
                declared: 2,
            },
            Defect::DeclaredDatCount {
                declared: 3,
                present: 2,
            },
            Defect::CollisionTableUnterminated { records: 2 },
            Defect::CollisionRecordAfterTerminator,
            Defect::CollisionPathUnterminated,
            Defect::CollisionPathNotAscii { at: 4 },
            Defect::CollisionPathKeyMismatch { hashes_to: 11 },
            Defect::CollisionRecordIsPlaceholder { packed: 1 },
            Defect::CollisionConflictIndexUnexpected {
                conflict_index: 2,
                records: 2,
            },
            Defect::CollisionRecordWithoutFlaggedEntry,
            Defect::FlaggedEntryWithoutRecords { records: 1 },
            Defect::FolderRowsNotAscending {
                hash: 1,
                previous: 2,
            },
            Defect::FolderRowPadNotZero { hash: 1, pad: 2 },
            Defect::FolderRowsDoNotTile {
                declared: 0x810,
                expected: 0x800,
            },
            Defect::FolderHashDisagreesWithEntry {
                folder: 1,
                entry_folder: 2,
            },
            Defect::DeclaredLength {
                declared: 0x880,
                actual: 0x800,
            },
            Defect::FormsDisagree {
                only_in: IndexKind::Index1,
                dat: 0,
                offset: 0x800,
            },
            Defect::EntryHeaderUnreadable {
                fault: ReadFault::Truncated,
                detail: "",
            },
            Defect::EntryContentTypeUnknown { declared: 9 },
            Defect::EntryHeaderMisaligned { header_size: 100 },
            Defect::OccupiedExceedsAllocated {
                occupied_units: 3,
                allocated_units: 1,
            },
            Defect::SlotsOverlap {
                slot_len: 256,
                next_offset: 0x880,
            },
            Defect::SlotBeforeDataRegion,
            Defect::SlotBeyondDataRegion {
                slot_end: 0x1000,
                region_end: 0x900,
            },
            Defect::GapNotEmptyBlockChain {
                len: 256,
                covered: 128,
                regions: 1,
            },
            Defect::EntryDecodeFailed {
                fault: ReadFault::BlockCorrupt,
                detail: "block header",
                produced: 0,
            },
        ]
    }

    #[test]
    fn a_container_path_round_trips_through_the_name_it_builds() {
        for repo in [Repo::Base, Repo::Ex(1), Repo::Ex(9)] {
            for file in [
                ContainerId::Index(IndexKind::Index1),
                ContainerId::Index(IndexKind::Index2),
                ContainerId::Dat(0),
                ContainerId::Dat(7),
            ] {
                let at = ContainerRef::new(repo, ArchiveId::new(0x0a, 3, 2), file);
                assert_eq!(
                    ContainerRef::from_relative_path(&at.relative_path()),
                    Some(at),
                    "{}",
                    at.relative_path().display()
                );
            }
        }
        // An archive is not a file, so its stem is not a container path in the other direction.
        let archive = ContainerRef::new(Repo::Base, ArchiveId::new(0, 0, 0), ContainerId::Archive);
        assert_eq!(
            ContainerRef::from_relative_path(&archive.relative_path()),
            None
        );
    }

    #[test]
    fn a_path_this_crate_would_not_build_names_no_container() {
        // A patch chain's target list holds every file the game has, most of which are not
        // containers, and a mod tool's leftovers sit in the same directories. Each of these has to
        // answer "none" rather than be bent into some container's identity.
        for path in [
            "ffxivboot.exe",
            "movie/ffxiv/00000.bk2",
            "sqpack/ffxiv/0a0000.win32.dat0.bck",
            "sqpack/ffxiv/0A0000.win32.index",
            "sqpack/ffxiv/0a0000.ps3.index",
            "sqpack/ffxiv/0a0000.win32.datx",
            "sqpack/ffxiv/0a0000.win32.dat999",
            "sqpack/nowhere/0a0000.win32.index",
            "sqpack/ffxiv/sub/0a0000.win32.index",
            "sqpack/ffxiv",
            "0a0000.win32.index",
        ] {
            assert_eq!(
                ContainerRef::from_relative_path(std::path::Path::new(path)),
                None,
                "{path}"
            );
        }
    }

    #[test]
    fn the_slug_list_names_every_variant_in_declaration_order() {
        let slugs: Vec<&str> = every_defect().into_iter().map(Defect::slug).collect();
        assert_eq!(slugs, DEFECT_SLUGS);
    }

    #[test]
    fn every_slug_is_a_distinct_kebab_case_key() {
        let mut seen = std::collections::BTreeSet::new();
        for slug in DEFECT_SLUGS {
            assert!(!slug.is_empty());
            assert!(
                slug.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
                    && !slug.starts_with('-')
                    && !slug.ends_with('-'),
                "{slug}"
            );
            assert!(seen.insert(*slug), "duplicate slug {slug}");
        }
    }

    #[test]
    fn an_unreadable_container_says_what_kind_of_read_failure_it_was() {
        // A container this process may not read, one that went away between the directory walk and the
        // read, and a device that answered with an error are three things to do three different things
        // about, and one line reading "io error" for all three leaves nothing to act on.
        let container =
            ContainerRef::new(Repo::Base, ArchiveId::new(0x0a, 0, 0), ContainerId::Dat(0));
        let cases = [
            (std::io::ErrorKind::PermissionDenied, "permission denied"),
            (std::io::ErrorKind::NotFound, "not on disk"),
            (std::io::ErrorKind::Other, "io error"),
        ];
        let mut faults = std::collections::BTreeSet::new();
        for (kind, label) in cases {
            let (fault, detail, offset) = read_fault(&Error::Io(std::io::Error::from(kind)));
            assert_eq!(detail, "");
            assert_eq!(offset, None);
            assert!(
                faults.insert(fault),
                "{kind:?} folds to a fault already seen"
            );
            let rendered = Finding {
                site: Site {
                    container,
                    offset: None,
                    key: None,
                },
                defect: Defect::ContainerUnreadable { fault, detail },
            }
            .to_string();
            assert_eq!(
                rendered,
                format!("sqpack/ffxiv/0a0000.win32.dat0: the container will not parse: {label}")
            );
        }
    }

    #[test]
    fn a_rendered_finding_names_its_file_its_offset_and_its_key() {
        let finding = Finding {
            site: Site {
                container: ContainerRef::new(
                    Repo::Base,
                    ArchiveId::new(0x0a, 0, 0),
                    ContainerId::Index(IndexKind::Index1),
                ),
                offset: Some(0x804),
                key: Some(0x04E9_A597_4CD3_CDEF),
            },
            defect: Defect::DuplicateEntryKey,
        };
        assert_eq!(
            finding.to_string(),
            "sqpack/ffxiv/0a0000.win32.index +0x000804 key=0x04e9a5974cd3cdef: \
             two entries carry this key"
        );
        // An archive-wide fault names the stem, since no one file is at fault.
        let archive = Finding {
            site: Site {
                container: finding.site.container.with_file(ContainerId::Archive),
                offset: None,
                key: None,
            },
            defect: Defect::DataFileMissing { dat: 3 },
        };
        assert_eq!(
            archive.to_string(),
            "sqpack/ffxiv/0a0000: dat3 is named but not on disk"
        );
    }

    #[test]
    fn findings_sort_by_container_then_by_position_then_by_defect() {
        // The report's order has to be a total one that does not depend on the order checks ran in:
        // a container with no offset sorts ahead of the same container's positioned findings.
        let index1 = ContainerRef::new(
            Repo::Base,
            ArchiveId::new(0x0a, 0, 0),
            ContainerId::Index(IndexKind::Index1),
        );
        let at = |container: ContainerRef, offset: Option<u64>, defect: Defect| Finding {
            site: Site {
                container,
                offset,
                key: None,
            },
            defect,
        };
        let mut findings = [
            at(
                index1.with_file(ContainerId::Dat(0)),
                Some(0x800),
                Defect::SlotBeforeDataRegion,
            ),
            at(index1, Some(0x900), Defect::DuplicateEntryKey),
            at(index1, Some(0x800), Defect::DuplicateEntryKey),
            at(index1, None, Defect::TrailingBytes { len: 4 }),
            at(
                index1.with_file(ContainerId::Archive),
                None,
                Defect::DataFileMissing { dat: 1 },
            ),
        ];
        findings.sort_unstable();
        let order: Vec<(Option<u64>, &str)> =
            findings.iter().map(|f| (f.site.offset, f.slug())).collect();
        assert_eq!(
            order,
            [
                (None, "data-file-missing"),
                (None, "trailing-bytes"),
                (Some(0x800), "duplicate-entry-key"),
                (Some(0x900), "duplicate-entry-key"),
                (Some(0x800), "slot-before-data-region"),
            ]
        );
    }

    #[test]
    fn the_budget_counts_what_it_drops_and_marks_the_container() {
        let container = ContainerRef::new(
            Repo::Base,
            ArchiveId::new(0x0a, 0, 0),
            ContainerId::Index(IndexKind::Index1),
        );
        let mut sink = Sink::new(container, 2);
        for i in 0..5 {
            sink.push_at(0x800 + i, Defect::DuplicateEntryKey);
        }
        let report = sink.finish(Totals::default());
        assert_eq!(report.findings.len(), 2);
        assert!(report.truncated);
        assert_eq!(report.totals.defects_suppressed, 3);
    }
}
