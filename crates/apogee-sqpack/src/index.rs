//! Index containers: the hash tables that say which `.dat` of an archive holds a file and where.
//!
//! An archive's `.index` (16-byte entries keyed by a folder hash paired with a file-name hash) and
//! `.index2` (8-byte entries keyed by the whole path's hash) hold the same file set and answer with
//! the same location. Both start with the common header, then carry a second header at `0x400`
//! describing four segments laid out back to back from `0x800`:
//!
//! | Segment | Holds |
//! |---|---|
//! | 1 | the entries, ascending by key |
//! | 2 | the collision table: one 256-byte record per colliding path, then a terminating record |
//! | 3 | 16-byte records whose role is not settled; `.index` only, carried verbatim |
//! | 4 | the folder table: `.index` only, one row per folder naming its run of segment-1 entries |
//!
//! A key whose entry has bit 0 set is a collision placeholder and carries no location at all: the
//! locations for that key live in segment 2, one record per colliding path, each holding the literal
//! path so the right one can be picked. [`Index::resolve`] does that; [`Index::lookup`] hands back the
//! placeholder so a caller working from a bare hash can see what it is. Segment 2 ends at a record
//! whose key is all ones in the kind's key width, which an `.index2` may spell in its low half alone.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::bytes::Cursor;
use crate::container::{COMMON_HEADER_LEN, CommonHeader, SqPackKind, parse_common_header};
use crate::error::{Error, Result};
use crate::hash::hash_path;

/// Where an index container's second header starts: immediately after the common header.
pub const INDEX_HEADER_OFFSET: u64 = COMMON_HEADER_LEN as u64;

/// The declared length of the index header, and so the offset of the first segment.
pub const INDEX_HEADER_LEN: u32 = 0x400;

/// The byte length of one `.index` entry.
pub const INDEX1_ENTRY_LEN: usize = 16;

/// The byte length of one `.index2` entry.
pub const INDEX2_ENTRY_LEN: usize = 8;

/// The byte length of one folder-table row.
pub const FOLDER_ROW_LEN: usize = 16;

/// The byte length of one collision-table record: a 16-byte prefix and a 240-byte path.
pub const COLLISION_RECORD_LEN: usize = 256;

/// The number of segments an index header describes.
pub const SEGMENT_COUNT: usize = 4;

/// Where each of the four segment descriptors sits in the file: the positions
/// [`parse_index_header`] reads them from, in header order. The reader takes them in sequence; a check
/// that has to name one has to address it.
pub(crate) const SEGMENT_DESCRIPTOR_AT: [u64; SEGMENT_COUNT] = [0x408, 0x454, 0x49C, 0x4E4];

/// Where the declared data-file count sits, between the first two segment descriptors.
pub(crate) const DATA_FILE_COUNT_AT: u64 = 0x450;

/// Where the index-kind word sits, after the fourth segment descriptor.
pub(crate) const INDEX_KIND_AT: u64 = 0x52C;

/// Where a collision record's path field starts: after its key, its location word and its conflict
/// index.
pub(crate) const COLLISION_PATH_AT: usize = 16;

/// The record length the third segment's size divides by. Nothing here claims to know what those
/// records mean; only that the segment is a whole number of them.
pub(crate) const UNCLASSIFIED_RECORD_LEN: usize = 16;

/// A cap on the file an [`Index::open`] will read. The largest archive in a full retail install is
/// `chara`'s at roughly 12 MiB, so this leaves two orders of magnitude of headroom while still
/// refusing to read a fabricated multi-gigabyte "index" into memory.
pub const DEFAULT_MAX_INDEX_BYTES: u64 = 256 << 20;

/// How much of an index file to reserve up front. The rest grows as bytes arrive, so a sparse or
/// misreported file cannot make a reservation out of a number nobody has read yet.
const READ_RESERVE_HINT: u64 = 1 << 20;

/// The path field of a collision record.
const COLLISION_PATH_LEN: usize = COLLISION_RECORD_LEN - COLLISION_PATH_AT;

/// The key an unused collision record carries in a filled key field; it terminates the table. Only an
/// `.index` key is as wide as the field holding it, so which keys terminate a table is
/// `IndexKind::terminates_collisions` rather than this constant alone.
const COLLISION_TERMINATOR: u64 = u64::MAX;

/// The byte length of one segment descriptor: offset, size, SHA-1, and 44 bytes of padding.
const SEGMENT_DESCRIPTOR_LEN: usize = 0x48;

/// The padding a segment descriptor carries after its SHA-1.
const SEGMENT_DESCRIPTOR_PAD: usize = SEGMENT_DESCRIPTOR_LEN - 4 - 4 - 20;

/// Allocation bounds enforced while opening an index file (all SqPack input is hostile).
#[derive(Debug, Clone, Copy)]
pub struct IndexLimits {
    /// Refuse to read an index file longer than this.
    pub max_index_bytes: u64,
}

impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            max_index_bytes: DEFAULT_MAX_INDEX_BYTES,
        }
    }
}

/// Which of the two index forms a container is, which is what decides how its entries are keyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum IndexKind {
    /// A `.index`: 16-byte entries keyed by the folder hash paired with the file-name hash. Declared
    /// as `0` in the header.
    Index1,
    /// An `.index2`: 8-byte entries keyed by the hash of the whole path. Declared as `2`.
    Index2,
}

impl IndexKind {
    /// The header word this kind is declared as.
    #[must_use]
    pub fn word(self) -> u32 {
        match self {
            IndexKind::Index1 => 0,
            IndexKind::Index2 => 2,
        }
    }

    /// The byte length of one of this kind's entries.
    #[must_use]
    pub fn entry_len(self) -> usize {
        match self {
            IndexKind::Index1 => INDEX1_ENTRY_LEN,
            IndexKind::Index2 => INDEX2_ENTRY_LEN,
        }
    }

    /// The file-name extension this kind is stored under.
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            IndexKind::Index1 => "index",
            IndexKind::Index2 => "index2",
        }
    }

    /// Whether `key` is the record that ends a collision table: all ones in this kind's key width.
    ///
    /// An `.index2` key is a 32-bit hash zero-extended into the record's 8-byte field, and a full
    /// retail install spells its terminator both ways: 8 of 59 archives write all ones in the low
    /// half alone and leave the unused half zero, the rest fill the field. Reading the unused half
    /// would take those 8 sentinels for a record keyed `0xFFFF_FFFF`, whose location word of zero
    /// decodes to the start of dat 0, which is that file's own header rather than anything in it.
    pub(crate) fn terminates_collisions(self, key: u64) -> bool {
        match self {
            IndexKind::Index1 => key == COLLISION_TERMINATOR,
            IndexKind::Index2 => key & u64::from(u32::MAX) == u64::from(u32::MAX),
        }
    }

    fn from_word(word: u32, offset: u64) -> Result<Self> {
        match word {
            0 => Ok(IndexKind::Index1),
            2 => Ok(IndexKind::Index2),
            _ => Err(Error::IndexCorrupt {
                offset,
                detail: "unknown index kind",
            }),
        }
    }
}

/// One segment's extent and the SHA-1 the container claims for its bytes. The hash is carried
/// verbatim: verifying it is the inspector's job, not something every open pays for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentDescriptor {
    /// Byte offset of the segment within the file. Not to be read when the segment is unused: a real
    /// container leaves an emptied segment's offset at the write cursor, at zero, or at the position it
    /// held before it was emptied, and all three occur across one install.
    pub offset: u32,
    /// Byte length of the segment, and the only field that decides whether the container carries it.
    pub size: u32,
    /// The SHA-1 the header claims over the segment's bytes.
    pub sha1: [u8; 20],
}

impl SegmentDescriptor {
    /// Whether the container carries this segment at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

/// The parsed index header at `0x400`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexHeader {
    /// The declared header length (expected [`INDEX_HEADER_LEN`]), recorded as read.
    pub header_size: u32,
    /// The declared format version (expected `1`), recorded as read.
    pub version: u32,
    /// Which index form this is.
    pub kind: IndexKind,
    /// The declared count of `.dat{n}` files the archive spans, recorded as read; [`crate::ArchiveInfo::dats`]
    /// is what a directory walk actually found beside it.
    pub data_file_count: u32,
    /// The four segment descriptors, in header order.
    pub segments: [SegmentDescriptor; SEGMENT_COUNT],
}

impl IndexHeader {
    /// The segment holding the entries.
    #[must_use]
    pub fn entry_segment(&self) -> &SegmentDescriptor {
        &self.segments[0]
    }

    /// The segment holding the collision table.
    #[must_use]
    pub fn collision_segment(&self) -> &SegmentDescriptor {
        &self.segments[1]
    }

    /// The third segment, whose role is not settled. Every real `.index2` leaves it empty; in a
    /// `.index` it holds 16-byte records of the shape `(0, u32, u32, 0)` that correlate with neither
    /// the entry count nor any free region observed in the dat files. It is described here so the
    /// inspector can account for its bytes without anything claiming to know what they mean.
    #[must_use]
    pub fn unclassified_segment(&self) -> &SegmentDescriptor {
        &self.segments[2]
    }

    /// The segment holding the folder table. Always empty in an `.index2`, which has no folder half
    /// to tabulate.
    #[must_use]
    pub fn folder_segment(&self) -> &SegmentDescriptor {
        &self.segments[3]
    }
}

/// Where an entry's bytes live inside the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataLocation {
    /// Which `.dat{n}` of the archive holds the entry.
    pub dat: u8,
    /// The entry's byte offset within that dat file.
    pub offset: u64,
}

impl DataLocation {
    /// Decode a location word: bit 0 marks a collision placeholder, bits 1-3 name the dat file, and
    /// the remaining bits are the offset in 8-byte units.
    #[must_use]
    fn from_packed(packed: u32) -> Self {
        // Masked to three bits, so the narrowing cannot lose anything.
        let dat = ((packed >> 1) & 0b111) as u8;
        Self {
            dat,
            offset: u64::from(packed & !0xF) * 8,
        }
    }
}

/// One entry: a key and the location word the container stores for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    /// In an `.index`, the folder hash in the high half and the file-name hash in the low half. In an
    /// `.index2`, the whole-path hash, zero-extended.
    pub key: u64,
    /// The raw location word, carried verbatim so a caller can see exactly what the container said.
    pub packed: u32,
}

impl IndexEntry {
    /// Whether this entry is a collision placeholder rather than a location.
    #[must_use]
    pub fn is_collision(&self) -> bool {
        self.packed & 1 != 0
    }

    /// Where the entry's bytes are, or `None` when it is a collision placeholder and the locations
    /// live in the collision table instead.
    #[must_use]
    pub fn location(&self) -> Option<DataLocation> {
        if self.is_collision() {
            None
        } else {
            Some(DataLocation::from_packed(self.packed))
        }
    }

    /// The folder half of an `.index` key. Meaningless for an `.index2` entry, whose key is whole.
    #[must_use]
    pub fn folder_hash(&self) -> u32 {
        // A `u64` shifted right by 32 always fits a `u32`.
        (self.key >> 32) as u32
    }

    /// The file-name half of an `.index` key, or an `.index2` key entire.
    #[must_use]
    pub fn file_hash(&self) -> u32 {
        // Truncation to the low half is the point.
        self.key as u32
    }
}

/// One folder-table row: a folder hash and the run of entries that belong to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderRow {
    /// The folder path's hash.
    pub hash: u32,
    /// Byte offset of this folder's run of entries, measured in the index file.
    pub entries_offset: u32,
    /// Byte length of that run.
    pub entries_size: u32,
}

impl FolderRow {
    /// How many entries the row claims. A folder table only appears in an `.index`, so the row's byte
    /// extent is always counted in 16-byte entries.
    #[must_use]
    pub fn entry_count(&self) -> u32 {
        self.entries_size / INDEX1_ENTRY_LEN as u32
    }
}

/// One collision-table record: a key several paths hash to, one of those paths in full, and the
/// location that path resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionRecord {
    /// The key this record disambiguates, in the same shape as an [`IndexEntry::key`].
    pub key: u64,
    /// The location word for this record's path.
    pub packed: u32,
    /// Which of the colliding paths this is, counting from zero.
    pub conflict_index: u32,
    /// The literal path, as the container spells it.
    pub path: String,
}

impl CollisionRecord {
    /// Whether this record is itself only a placeholder, which no real container writes.
    #[must_use]
    pub fn is_collision(&self) -> bool {
        self.packed & 1 != 0
    }

    /// Where this record's path lives, or `None` when the record carries a placeholder rather than a
    /// location. Guarded exactly as [`IndexEntry::location`] is: decoding a placeholder would yield
    /// offset zero, which is the dat file's own header rather than any file in it.
    #[must_use]
    pub fn location(&self) -> Option<DataLocation> {
        if self.is_collision() {
            None
        } else {
            Some(DataLocation::from_packed(self.packed))
        }
    }
}

/// A parsed index container.
#[derive(Debug, Clone)]
pub struct Index {
    common: CommonHeader,
    header: IndexHeader,
    entries: Vec<IndexEntry>,
    folders: Vec<FolderRow>,
    collisions: Vec<CollisionRecord>,
    sorted: bool,
}

impl Index {
    /// Read and parse an index container, refusing a file larger than [`DEFAULT_MAX_INDEX_BYTES`].
    ///
    /// # Errors
    /// - [`Error::Io`] if the file cannot be read.
    /// - [`Error::LimitExceeded`] if the file is larger than the default cap.
    /// - Everything [`Index::parse`] raises.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_limits(path, &IndexLimits::default())
    }

    /// Read and parse an index container under caller-chosen bounds.
    ///
    /// # Errors
    /// - [`Error::Io`] if the file cannot be read.
    /// - [`Error::LimitExceeded`] if the file is larger than `limits.max_index_bytes`.
    /// - Everything [`Index::parse`] raises.
    pub fn open_with_limits(path: impl AsRef<Path>, limits: &IndexLimits) -> Result<Self> {
        Self::parse(&read_capped(path.as_ref(), limits)?)
    }

    /// Parse an index container from its bytes.
    ///
    /// Every allocation is bounded by the input's own length, within the constant factor a lossy
    /// UTF-8 conversion of a collision record's path can add: a segment that runs past the end of the
    /// buffer is a truncation, never a reservation.
    ///
    /// # Errors
    /// - [`Error::BadMagic`] / [`Error::UnsupportedPlatform`] from the common header.
    /// - [`Error::Truncated`] if the header or any declared segment runs past the end.
    /// - [`Error::IndexCorrupt`] if the container is not an index, declares an unknown index kind, or
    ///   sizes a segment to something other than a whole number of its records.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let common = parse_common_header(buf)?;
        if common.kind != SqPackKind::Index {
            return Err(Error::IndexCorrupt {
                offset: 0x14,
                detail: "not an index container",
            });
        }

        let tail = buf
            .get(COMMON_HEADER_LEN..)
            .ok_or_else(|| Error::Truncated {
                offset: buf.len() as u64,
                needed: (COMMON_HEADER_LEN - buf.len()) as u64,
            })?;
        let header = parse_index_header(&mut Cursor::new(tail, INDEX_HEADER_OFFSET))?;

        let entry_len = header.kind.entry_len();
        let entries = parse_entries(
            segment(
                buf,
                header.entry_segment(),
                entry_len,
                "entry segment is not a whole number of entries",
            )?,
            header.entry_segment().offset,
            header.kind,
        )?;
        let collisions = parse_collisions(
            segment(
                buf,
                header.collision_segment(),
                COLLISION_RECORD_LEN,
                "collision segment is not a whole number of records",
            )?,
            header.collision_segment().offset,
            header.kind,
        )?;
        let folders = parse_folders(
            segment(
                buf,
                header.folder_segment(),
                FOLDER_ROW_LEN,
                "folder segment is not a whole number of rows",
            )?,
            header.folder_segment().offset,
        )?;
        // The third segment is not interpreted, but its extent is still checked, so what
        // `unclassified_segment` hands an inspector is bytes that exist. A record length of one makes
        // no claim about a record layout nothing here has settled.
        segment(
            buf,
            header.unclassified_segment(),
            1,
            "unclassified segment",
        )?;

        // Real containers sort their entries, which is what makes a lookup a binary search. A
        // rewritten one might not, so the order is measured rather than assumed and an unsorted table
        // falls back to a scan instead of quietly missing entries it holds.
        let sorted = entries.windows(2).all(|w| w[0].key <= w[1].key);

        Ok(Self {
            common,
            header,
            entries,
            folders,
            collisions,
            sorted,
        })
    }

    /// The container's common header.
    #[must_use]
    pub fn common_header(&self) -> &CommonHeader {
        &self.common
    }

    /// The container's index header, including its segment table.
    #[must_use]
    pub fn header(&self) -> &IndexHeader {
        &self.header
    }

    /// Which index form this is.
    #[must_use]
    pub fn kind(&self) -> IndexKind {
        self.header.kind
    }

    /// The entries, in file order.
    #[must_use]
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    /// The folder table, in file order. Empty for an `.index2`.
    #[must_use]
    pub fn folders(&self) -> &[FolderRow] {
        &self.folders
    }

    /// The collision table, in file order, with the terminating record dropped.
    #[must_use]
    pub fn collisions(&self) -> &[CollisionRecord] {
        &self.collisions
    }

    /// Whether the entries are in ascending key order, which is what a real container guarantees and
    /// what lets a lookup binary-search rather than scan.
    #[must_use]
    pub fn is_sorted(&self) -> bool {
        self.sorted
    }

    /// The entries a folder row names, or `None` when the row does not describe a whole run of
    /// entries inside the entry segment. A real container's rows tile the segment exactly; a `None`
    /// here is a finding for the inspector, not a reason to refuse the whole container.
    #[must_use]
    pub fn folder_entries(&self, row: &FolderRow) -> Option<&[IndexEntry]> {
        // A folder table only appears in an `.index`, whose entries are 16 bytes; reading a row's
        // byte extent against an `.index2`'s 8-byte entries would name a real but wrong run.
        if self.header.kind != IndexKind::Index1 {
            return None;
        }
        let base = self.header.entry_segment().offset;
        let start = row.entries_offset.checked_sub(base)?;
        let unit = INDEX1_ENTRY_LEN as u32;
        if !start.is_multiple_of(unit) || !row.entries_size.is_multiple_of(unit) {
            return None;
        }
        let first = start as usize / INDEX1_ENTRY_LEN;
        let count = row.entries_size as usize / INDEX1_ENTRY_LEN;
        self.entries.get(first..first.checked_add(count)?)
    }

    /// The entry for `key`, or `None` if the container has none. When several entries share a key,
    /// the first in file order wins.
    #[must_use]
    pub fn lookup(&self, key: u64) -> Option<&IndexEntry> {
        if !self.sorted {
            return self.entries.iter().find(|e| e.key == key);
        }
        let hit = self.entries.binary_search_by(|e| e.key.cmp(&key)).ok()?;
        // A binary search over duplicates lands anywhere in the run; walking back makes the answer the
        // same one a scan would give.
        let mut first = hit;
        while first > 0 && self.entries.get(first - 1).is_some_and(|e| e.key == key) {
            first -= 1;
        }
        self.entries.get(first)
    }

    /// The collision records filed under `key`.
    pub fn collisions_for(&self, key: u64) -> impl Iterator<Item = &CollisionRecord> {
        self.collisions.iter().filter(move |c| c.key == key)
    }

    /// Resolve a game path to the location the container holds for it, or `None` if it holds none.
    ///
    /// A key that collides carries no location of its own, so the collision table is searched for the
    /// record spelling this path, matched the same case-insensitive way the hash itself folds it.
    ///
    /// # Errors
    /// [`Error::SynonymUnresolved`] if the path's key is a collision placeholder and no collision
    /// record spells that path: the container knows the key is shared but cannot say which of the
    /// sharers was asked for, and answering with either one's bytes would be a guess.
    pub fn resolve(&self, path: &str) -> Result<Option<DataLocation>> {
        let hash = hash_path(path);
        let key = match self.header.kind {
            IndexKind::Index1 => hash.key(),
            IndexKind::Index2 => u64::from(hash.full),
        };
        let Some(entry) = self.lookup(key) else {
            return Ok(None);
        };
        if let Some(location) = entry.location() {
            return Ok(Some(location));
        }
        self.collisions_for(key)
            .find(|record| record.path.eq_ignore_ascii_case(path))
            .and_then(CollisionRecord::location)
            .map(Some)
            .ok_or_else(|| Error::SynonymUnresolved {
                key: format!("{key:#018x}"),
            })
    }
}

/// Read a whole index container into memory, refusing one longer than `limits` allows.
///
/// Answers with the bytes rather than a parse, because the checks that judge a container need both:
/// the two header digests and the four segment digests cover bytes the parsed form no longer carries.
///
/// # Errors
/// - [`Error::Io`] if the file cannot be read.
/// - [`Error::LimitExceeded`] if it is longer than `limits.max_index_bytes`.
pub(crate) fn read_capped(path: &Path, limits: &IndexLimits) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    if len > limits.max_index_bytes {
        return Err(Error::LimitExceeded);
    }
    // The cap is enforced on what is actually read, not on what the directory entry claims: a
    // character device or a pipe reports a length of zero and would otherwise be read forever.
    // Reading one byte past the cap is what tells the two apart from a file that exactly fills it.
    let hint = len.min(READ_RESERVE_HINT);
    let mut buf = Vec::with_capacity(usize::try_from(hint).unwrap_or(0));
    file.take(limits.max_index_bytes.saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > limits.max_index_bytes {
        return Err(Error::LimitExceeded);
    }
    Ok(buf)
}

/// Parse the index header at `0x400`. The cursor's base is that absolute offset, so a short read
/// reports where in the file it ran out.
fn parse_index_header(c: &mut Cursor<'_>) -> Result<IndexHeader> {
    let header_size = c.u32_le()?;
    let version = c.u32_le()?;
    let entry_segment = parse_segment_descriptor(c)?;
    let data_file_count = c.u32_le()?;
    let collision_segment = parse_segment_descriptor(c)?;
    let unclassified_segment = parse_segment_descriptor(c)?;
    let folder_segment = parse_segment_descriptor(c)?;
    let kind_offset = c.offset();
    let kind = IndexKind::from_word(c.u32_le()?, kind_offset)?;
    Ok(IndexHeader {
        header_size,
        version,
        kind,
        data_file_count,
        segments: [
            entry_segment,
            collision_segment,
            unclassified_segment,
            folder_segment,
        ],
    })
}

fn parse_segment_descriptor(c: &mut Cursor<'_>) -> Result<SegmentDescriptor> {
    let offset = c.u32_le()?;
    let size = c.u32_le()?;
    let raw = c.take(20)?;
    let sha1 = <[u8; 20]>::try_from(raw).map_err(|_| Error::IndexCorrupt {
        offset: c.offset(),
        detail: "array conversion",
    })?;
    c.skip(SEGMENT_DESCRIPTOR_PAD)?; // reserved
    Ok(SegmentDescriptor { offset, size, sha1 })
}

/// Borrow a declared segment's bytes, refusing one that runs past the end of the file or that is not
/// a whole number of `unit`-sized records. `ragged` is the fault reported for the latter.
fn segment<'a>(
    buf: &'a [u8],
    descriptor: &SegmentDescriptor,
    unit: usize,
    ragged: &'static str,
) -> Result<&'a [u8]> {
    if descriptor.is_empty() {
        return Ok(&[]);
    }
    let start = usize::try_from(descriptor.offset).map_err(|_| Error::LimitExceeded)?;
    let len = usize::try_from(descriptor.size).map_err(|_| Error::LimitExceeded)?;
    let end = start.checked_add(len).ok_or(Error::IndexCorrupt {
        offset: u64::from(descriptor.offset),
        detail: "segment extent overflows",
    })?;
    let slice = buf.get(start..end).ok_or_else(|| Error::Truncated {
        offset: buf.len() as u64,
        needed: end.saturating_sub(buf.len()) as u64,
    })?;
    if !len.is_multiple_of(unit) {
        return Err(Error::IndexCorrupt {
            offset: u64::from(descriptor.offset),
            detail: ragged,
        });
    }
    Ok(slice)
}

fn parse_entries(seg: &[u8], base: u32, kind: IndexKind) -> Result<Vec<IndexEntry>> {
    let entry_len = kind.entry_len();
    let mut c = Cursor::new(seg, u64::from(base));
    let mut out = Vec::with_capacity(seg.len() / entry_len);
    while c.remaining() >= entry_len {
        let (key, packed) = match kind {
            IndexKind::Index1 => {
                let key = c.u64_le()?;
                let packed = c.u32_le()?;
                c.skip(4)?; // reserved
                (key, packed)
            }
            IndexKind::Index2 => {
                let key = u64::from(c.u32_le()?);
                (key, c.u32_le()?)
            }
        };
        out.push(IndexEntry { key, packed });
    }
    Ok(out)
}

fn parse_folders(seg: &[u8], base: u32) -> Result<Vec<FolderRow>> {
    let mut c = Cursor::new(seg, u64::from(base));
    let mut out = Vec::with_capacity(seg.len() / FOLDER_ROW_LEN);
    while c.remaining() >= FOLDER_ROW_LEN {
        let hash = c.u32_le()?;
        let entries_offset = c.u32_le()?;
        let entries_size = c.u32_le()?;
        c.skip(4)?; // reserved
        out.push(FolderRow {
            hash,
            entries_offset,
            entries_size,
        });
    }
    Ok(out)
}

fn parse_collisions(seg: &[u8], base: u32, kind: IndexKind) -> Result<Vec<CollisionRecord>> {
    let mut c = Cursor::new(seg, u64::from(base));
    let mut out = Vec::new();
    while c.remaining() >= COLLISION_RECORD_LEN {
        let key = c.u64_le()?;
        let packed = c.u32_le()?;
        let conflict_index = c.u32_le()?;
        let raw = c.take(COLLISION_PATH_LEN)?;
        if kind.terminates_collisions(key) {
            break;
        }
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        out.push(CollisionRecord {
            key,
            packed,
            conflict_index,
            // The path is ASCII in every record observed; a container that says otherwise is
            // reported as it reads rather than refused, since the match against it will simply fail.
            path: String::from_utf8_lossy(&raw[..end]).into_owned(),
        });
    }
    Ok(out)
}

/// A synthetic index writer for tests, compiled only for them and for the `test-fixtures` feature.
/// This crate reads archives and never writes them, so this is not a write API: the only reason to
/// lay these bytes out is to prove the reader reads them. It stays crate-private either way, since
/// what the feature publishes is the whole archive an [`crate::fixtures::ArchiveFixture`] lays down.
///
/// What it writes by default is byte-faithful down to the six digests a real container carries, so a
/// container it builds is one the integrity checks find nothing wrong with. Every knob past that
/// spells one measured shape differently, so a check can be shown to fire on exactly that difference.
#[cfg(any(test, feature = "test-fixtures"))]
pub(crate) mod build {
    // Most of the knobs below exist for one check's own test, so the module reads as dead whenever
    // the feature compiles it without the test harness. Keeping the set complete is the point: a
    // check is shown to fire by spelling exactly one measured shape differently.
    #![allow(dead_code)]

    use super::*;
    use crate::bytes;
    use crate::container::{COMMON_HEADER_LEN, SQPACK_MAGIC};
    use crate::integrity::{HeaderId, SELF_HASH_AT, SELF_HASH_LEN, self_hash_slot, sha1};

    /// How the record that ends a collision table is spelled.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub(crate) enum Terminator {
        /// All ones across the record's whole 8-byte key field, which every `.index` and most
        /// `.index2` files write.
        #[default]
        Wide,
        /// All ones in an `.index2`'s 32-bit key width, leaving the unused half zero, which some
        /// archives write instead. Nothing for an `.index`, whose key fills the field.
        Narrow,
        /// No terminating record at all, which no real container writes.
        Absent,
    }

    /// Builds a byte-faithful index container: common header, index header, then the segments laid
    /// out back to back from `0x800` in the order a real container writes them.
    #[derive(Debug, Clone)]
    pub(crate) struct IndexBuilder {
        kind: IndexKind,
        data_file_count: u32,
        entries: Vec<IndexEntry>,
        entry_pads: Vec<(usize, u32)>,
        sort_entries: bool,
        collisions: Vec<CollisionRecord>,
        collision_path_tail: Vec<u8>,
        terminator: Terminator,
        folders: Option<Vec<FolderRow>>,
        folder_pads: Vec<(usize, u32)>,
        unclassified: Vec<u8>,
        header_size: u32,
        version: u32,
        kind_word: Option<u32>,
        container_kind: u32,
        segment_sha1: [Option<[u8; 20]>; SEGMENT_COUNT],
        zero_segment_hashes: bool,
        self_hashes: [Option<[u8; 20]>; 2],
        zero_self_hashes: bool,
        zero_empty_segment_offsets: bool,
        header_pokes: Vec<(usize, Vec<u8>)>,
        segment_gaps: [usize; SEGMENT_COUNT],
        trailing: usize,
    }

    impl IndexBuilder {
        pub(crate) fn new(kind: IndexKind) -> Self {
            Self {
                kind,
                data_file_count: 1,
                entries: Vec::new(),
                entry_pads: Vec::new(),
                sort_entries: false,
                collisions: Vec::new(),
                collision_path_tail: Vec::new(),
                terminator: Terminator::default(),
                folders: None,
                folder_pads: Vec::new(),
                unclassified: Vec::new(),
                header_size: INDEX_HEADER_LEN,
                version: 1,
                kind_word: None,
                container_kind: 2,
                segment_sha1: [None; SEGMENT_COUNT],
                zero_segment_hashes: false,
                self_hashes: [None; 2],
                zero_self_hashes: false,
                zero_empty_segment_offsets: false,
                header_pokes: Vec::new(),
                segment_gaps: [0; SEGMENT_COUNT],
                trailing: 0,
            }
        }

        /// Add an entry. Keys are written in the order given, so a test can hand over an unsorted
        /// table on purpose.
        pub(crate) fn entry(&mut self, key: u64, packed: u32) -> &mut Self {
            self.entries.push(IndexEntry { key, packed });
            self
        }

        /// Add an entry for `path`, keyed the way this builder's kind keys it.
        pub(crate) fn path(&mut self, path: &str, packed: u32) -> &mut Self {
            let hash = hash_path(path);
            let key = match self.kind {
                IndexKind::Index1 => hash.key(),
                IndexKind::Index2 => u64::from(hash.full),
            };
            self.entry(key, packed)
        }

        /// Write the entries in ascending key order, which is what a real container does and what
        /// makes a derived folder table's rows ascend: the derivation groups *consecutive* equal
        /// folder hashes, so an unsorted table cannot produce a coherent one.
        pub(crate) fn sort_entries(&mut self) -> &mut Self {
            self.sort_entries = true;
            self
        }

        /// Write `word` into the reserved word of the entry at `position`, which only an `.index`
        /// entry has.
        pub(crate) fn entry_pad(&mut self, position: usize, word: u32) -> &mut Self {
            self.entry_pads.push((position, word));
            self
        }

        /// Add a collision record.
        pub(crate) fn collision(
            &mut self,
            key: u64,
            packed: u32,
            conflict_index: u32,
            path: &str,
        ) -> &mut Self {
            self.collisions.push(CollisionRecord {
                key,
                packed,
                conflict_index,
                path: path.to_owned(),
            });
            self
        }

        /// Leave `tail` in every collision record's path field after the path's terminating NUL, which
        /// is what a real record carries: the field is never zeroed, so it holds whatever longer path
        /// was written there before.
        pub(crate) fn collision_path_tail(&mut self, tail: &[u8]) -> &mut Self {
            self.collision_path_tail = tail.to_vec();
            self
        }

        /// How to spell the record that ends the collision table.
        pub(crate) fn terminator(&mut self, terminator: Terminator) -> &mut Self {
            self.terminator = terminator;
            self
        }

        pub(crate) fn data_file_count(&mut self, n: u32) -> &mut Self {
            self.data_file_count = n;
            self
        }

        /// Write a folder table verbatim instead of deriving one from the entries.
        pub(crate) fn folders(&mut self, rows: Vec<FolderRow>) -> &mut Self {
            self.folders = Some(rows);
            self
        }

        /// Write `word` into the reserved word of the folder row at `position`.
        pub(crate) fn folder_pad(&mut self, position: usize, word: u32) -> &mut Self {
            self.folder_pads.push((position, word));
            self
        }

        /// Fill the third segment with `len` bytes, whatever its role turns out to be.
        pub(crate) fn unclassified(&mut self, len: usize) -> &mut Self {
            self.unclassified = (0..len).map(|i| (i % 251) as u8).collect();
            self
        }

        /// Declare an index kind the format does not define.
        pub(crate) fn kind_word(&mut self, word: u32) -> &mut Self {
            self.kind_word = Some(word);
            self
        }

        /// Declare a container type other than "index" in the common header.
        pub(crate) fn container_kind(&mut self, kind: u32) -> &mut Self {
            self.container_kind = kind;
            self
        }

        /// Declare `sha1` for one segment instead of the digest of its bytes.
        pub(crate) fn segment_sha1(&mut self, segment: usize, sha1: [u8; 20]) -> &mut Self {
            self.segment_sha1[segment] = Some(sha1);
            self
        }

        /// Declare all zeros for every non-empty segment, which claims nothing about their bytes.
        pub(crate) fn zero_segment_hashes(&mut self) -> &mut Self {
            self.zero_segment_hashes = true;
            self
        }

        /// Declare `sha1` for one header instead of the digest of its own leading bytes.
        pub(crate) fn self_hash(&mut self, header: HeaderId, sha1: [u8; 20]) -> &mut Self {
            self.self_hashes[self_hash_slot(header)] = Some(sha1);
            self
        }

        /// Declare all zeros for both headers' own digests.
        pub(crate) fn zero_self_hashes(&mut self) -> &mut Self {
            self.zero_self_hashes = true;
            self
        }

        /// Declare zero rather than the write cursor as an empty segment's offset, which is the other
        /// shape a real container writes.
        pub(crate) fn zero_empty_segment_offsets(&mut self) -> &mut Self {
            self.zero_empty_segment_offsets = true;
            self
        }

        /// Write `bytes` verbatim at absolute offset `at`, which must be inside the two headers.
        /// Applied before the headers' own digests are computed, so a poke inside a hashed run leaves
        /// the container's hashes correct and a poke past one does not.
        pub(crate) fn header_pad(&mut self, at: usize, bytes: &[u8]) -> &mut Self {
            self.header_pokes.push((at, bytes.to_vec()));
            self
        }

        /// Leave `len` bytes between the previous segment and segment `index`, so the segments no
        /// longer tile.
        pub(crate) fn segment_gap(&mut self, index: usize, len: usize) -> &mut Self {
            self.segment_gaps[index] = len;
            self
        }

        /// Leave `len` bytes past the last segment.
        pub(crate) fn trailing(&mut self, len: usize) -> &mut Self {
            self.trailing = len;
            self
        }

        pub(crate) fn header_size(&mut self, size: u32) -> &mut Self {
            self.header_size = size;
            self
        }

        pub(crate) fn version(&mut self, version: u32) -> &mut Self {
            self.version = version;
            self
        }

        /// The folder table a real container would carry for these entries: one row per distinct
        /// folder hash, in the order the entries first mention it, each naming its run.
        fn derived_folders(entries: &[IndexEntry], entry_base: u32) -> Vec<FolderRow> {
            let mut rows: Vec<FolderRow> = Vec::new();
            for (i, entry) in entries.iter().enumerate() {
                let hash = entry.folder_hash();
                let offset = entry_base + (i * INDEX1_ENTRY_LEN) as u32;
                match rows.last_mut() {
                    Some(row) if row.hash == hash => {
                        row.entries_size += INDEX1_ENTRY_LEN as u32;
                    }
                    _ => rows.push(FolderRow {
                        hash,
                        entries_offset: offset,
                        entries_size: INDEX1_ENTRY_LEN as u32,
                    }),
                }
            }
            rows
        }

        /// A record's 240-byte path field: the path, its terminating NUL, then whatever the previous
        /// occupant left. A path that fills the field is written without a NUL, which is a shape no
        /// real record has.
        fn path_field(&self, path: &str) -> Vec<u8> {
            let mut field = vec![0u8; COLLISION_PATH_LEN];
            let raw = path.as_bytes();
            let len = raw.len().min(COLLISION_PATH_LEN);
            field[..len].copy_from_slice(&raw[..len]);
            let tail_at = len + 1;
            if tail_at < COLLISION_PATH_LEN {
                let tail = &self.collision_path_tail;
                let tail_len = tail.len().min(COLLISION_PATH_LEN - tail_at);
                field[tail_at..tail_at + tail_len].copy_from_slice(&tail[..tail_len]);
            }
            field
        }

        fn word_for(pads: &[(usize, u32)], position: usize) -> u32 {
            pads.iter()
                .find(|(at, _)| *at == position)
                .map_or(0, |(_, word)| *word)
        }

        pub(crate) fn bytes(&self) -> Vec<u8> {
            let mut entries = self.entries.clone();
            if self.sort_entries {
                entries.sort_by_key(|entry| entry.key);
            }

            let mut entry_bytes = Vec::new();
            for (i, entry) in entries.iter().enumerate() {
                match self.kind {
                    IndexKind::Index1 => {
                        entry_bytes.extend_from_slice(&bytes::write_u64_le(entry.key));
                        entry_bytes.extend_from_slice(&bytes::write_u32_le(entry.packed));
                        entry_bytes.extend_from_slice(&bytes::write_u32_le(Self::word_for(
                            &self.entry_pads,
                            i,
                        )));
                    }
                    IndexKind::Index2 => {
                        entry_bytes.extend_from_slice(&bytes::write_u32_le(entry.file_hash()));
                        entry_bytes.extend_from_slice(&bytes::write_u32_le(entry.packed));
                    }
                }
            }

            // A real container always writes the terminating record, so an empty table is 256 bytes.
            let mut collision_bytes = Vec::new();
            for record in &self.collisions {
                collision_bytes.extend_from_slice(&bytes::write_u64_le(record.key));
                collision_bytes.extend_from_slice(&bytes::write_u32_le(record.packed));
                collision_bytes.extend_from_slice(&bytes::write_u32_le(record.conflict_index));
                collision_bytes.extend_from_slice(&self.path_field(&record.path));
            }
            if self.terminator != Terminator::Absent {
                let key = match (self.terminator, self.kind) {
                    (Terminator::Narrow, IndexKind::Index2) => u64::from(u32::MAX),
                    _ => COLLISION_TERMINATOR,
                };
                collision_bytes.extend_from_slice(&bytes::write_u64_le(key));
                collision_bytes.extend_from_slice(&bytes::write_u32_le(0));
                collision_bytes.extend_from_slice(&bytes::write_u32_le(u32::MAX));
                collision_bytes.resize(collision_bytes.len() + COLLISION_PATH_LEN, 0);
            }

            let entry_base =
                COMMON_HEADER_LEN as u32 + INDEX_HEADER_LEN + self.segment_gaps[0] as u32;
            let folder_rows = match (&self.folders, self.kind) {
                (Some(rows), _) => rows.clone(),
                (None, IndexKind::Index1) => Self::derived_folders(&entries, entry_base),
                (None, IndexKind::Index2) => Vec::new(),
            };
            let mut folder_bytes = Vec::new();
            for (i, row) in folder_rows.iter().enumerate() {
                folder_bytes.extend_from_slice(&bytes::write_u32_le(row.hash));
                folder_bytes.extend_from_slice(&bytes::write_u32_le(row.entries_offset));
                folder_bytes.extend_from_slice(&bytes::write_u32_le(row.entries_size));
                folder_bytes
                    .extend_from_slice(&bytes::write_u32_le(Self::word_for(&self.folder_pads, i)));
            }

            let payloads: [&[u8]; SEGMENT_COUNT] = [
                &entry_bytes,
                &collision_bytes,
                &self.unclassified,
                &folder_bytes,
            ];
            let mut body = Vec::new();
            let mut cursor = COMMON_HEADER_LEN as u32 + INDEX_HEADER_LEN;
            let mut descriptors = [(0u32, 0u32); SEGMENT_COUNT];
            for (i, payload) in payloads.iter().enumerate() {
                if payload.is_empty() {
                    // A real container leaves an emptied segment's offset at the write cursor, or at
                    // zero; both shapes occur, and only the size says the segment is not there.
                    let offset = if self.zero_empty_segment_offsets {
                        0
                    } else {
                        cursor
                    };
                    descriptors[i] = (offset, 0);
                    continue;
                }
                body.extend(std::iter::repeat_n(0u8, self.segment_gaps[i]));
                cursor += self.segment_gaps[i] as u32;
                descriptors[i] = (cursor, payload.len() as u32);
                body.extend_from_slice(payload);
                cursor += payload.len() as u32;
            }
            body.extend(std::iter::repeat_n(0u8, self.trailing));

            let mut out = vec![0u8; COMMON_HEADER_LEN + INDEX_HEADER_LEN as usize];
            out[0..8].copy_from_slice(&SQPACK_MAGIC);
            out[0x0C..0x10].copy_from_slice(&bytes::write_u32_le(COMMON_HEADER_LEN as u32));
            out[0x10..0x14].copy_from_slice(&bytes::write_u32_le(1));
            out[0x14..0x18].copy_from_slice(&bytes::write_u32_le(self.container_kind));

            let head = COMMON_HEADER_LEN;
            out[head..head + 4].copy_from_slice(&bytes::write_u32_le(self.header_size));
            out[head + 4..head + 8].copy_from_slice(&bytes::write_u32_le(self.version));
            for (i, (offset, size)) in descriptors.iter().enumerate() {
                let at = SEGMENT_DESCRIPTOR_AT[i] as usize;
                out[at..at + 4].copy_from_slice(&bytes::write_u32_le(*offset));
                out[at + 4..at + 8].copy_from_slice(&bytes::write_u32_le(*size));
                if *size == 0 {
                    // An unused descriptor declares the digest of nothing, the way a real one does.
                    out[at + 8..at + 8 + SELF_HASH_LEN].copy_from_slice(&sha1(&[]));
                    continue;
                }
                let digest = self.segment_sha1[i].unwrap_or_else(|| {
                    if self.zero_segment_hashes {
                        [0; 20]
                    } else {
                        sha1(payloads[i])
                    }
                });
                out[at + 8..at + 8 + SELF_HASH_LEN].copy_from_slice(&digest);
            }
            let count_at = DATA_FILE_COUNT_AT as usize;
            out[count_at..count_at + 4].copy_from_slice(&bytes::write_u32_le(self.data_file_count));
            let kind_at = INDEX_KIND_AT as usize;
            let kind_word = self.kind_word.unwrap_or_else(|| self.kind.word());
            out[kind_at..kind_at + 4].copy_from_slice(&bytes::write_u32_le(kind_word));
            for (at, poke) in &self.header_pokes {
                out[*at..*at + poke.len()].copy_from_slice(poke);
            }

            out.extend_from_slice(&body);

            // Each header's own digest covers everything before it, so it is written last: a poke into
            // a hashed run then leaves a container whose hashes are still right about its bytes.
            for header in [HeaderId::Common, HeaderId::Second] {
                let at = header.starts_at();
                let digest = self.self_hashes[self_hash_slot(header)].unwrap_or_else(|| {
                    if self.zero_self_hashes {
                        [0; 20]
                    } else {
                        sha1(&out[at..at + SELF_HASH_AT])
                    }
                });
                let field = at + SELF_HASH_AT;
                out[field..field + SELF_HASH_LEN].copy_from_slice(&digest);
            }
            out
        }
    }

    /// A location word for `dat` at `offset`, the way a container packs one. Real dat entries start
    /// on a 128-byte boundary, which is what leaves the low four bits free for the dat index and the
    /// collision flag; the mask keeps that true for any offset a test hands over.
    pub(crate) fn packed(dat: u8, offset: u64) -> u32 {
        let units = u32::try_from(offset / 8).unwrap_or(u32::MAX);
        (units & !0xF) | (u32::from(dat) << 1)
    }
}

#[cfg(test)]
mod tests {
    use super::build::{IndexBuilder, Terminator, packed};
    use super::*;
    use crate::bytes;
    use crate::container::Platform;
    use proptest::prelude::*;

    #[test]
    fn an_index1_container_round_trips_through_the_reader() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(3)
            .path("common/font/font1.tex", packed(0, 0x100_000))
            .path("common/font/font2.tex", packed(2, 0x200_000))
            .path("exd/root.exl", packed(1, 0x300_000));
        let index = Index::parse(&b.bytes()).unwrap();

        assert_eq!(index.kind(), IndexKind::Index1);
        assert_eq!(index.common_header().platform, Platform::Win32);
        assert_eq!(index.header().data_file_count, 3);
        assert_eq!(index.entries().len(), 3);
        assert_eq!(
            index.resolve("common/font/font1.tex").unwrap(),
            Some(DataLocation {
                dat: 0,
                offset: 0x100_000
            })
        );
        assert_eq!(
            index.resolve("exd/root.exl").unwrap(),
            Some(DataLocation {
                dat: 1,
                offset: 0x300_000
            })
        );
        assert_eq!(index.resolve("exd/nothing.exl").unwrap(), None);
    }

    #[test]
    fn an_index2_container_answers_the_same_locations() {
        let paths = [
            ("common/font/font1.tex", packed(0, 0x100_000)),
            ("exd/root.exl", packed(1, 0x300_000)),
        ];
        let mut one = IndexBuilder::new(IndexKind::Index1);
        let mut two = IndexBuilder::new(IndexKind::Index2);
        for (path, loc) in paths {
            one.path(path, loc);
            two.path(path, loc);
        }
        let one = Index::parse(&one.bytes()).unwrap();
        let two = Index::parse(&two.bytes()).unwrap();

        assert_eq!(two.kind(), IndexKind::Index2);
        assert!(two.folders().is_empty(), "an index2 has no folder table");
        for (path, _) in paths {
            assert_eq!(
                one.resolve(path).unwrap(),
                two.resolve(path).unwrap(),
                "{path}"
            );
        }
    }

    #[test]
    fn the_folder_table_names_each_folders_run_of_entries() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.path("common/font/font1.tex", packed(0, 0x80))
            .path("common/font/font2.tex", packed(0, 0x100))
            .path("exd/root.exl", packed(0, 0x180));
        let index = Index::parse(&b.bytes()).unwrap();

        let folders = index.folders();
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].hash, hash_path("common/font").full);
        assert_eq!(folders[0].entry_count(), 2);
        assert_eq!(folders[1].hash, hash_path("exd").full);
        assert_eq!(folders[1].entry_count(), 1);

        let run = index.folder_entries(&folders[0]).unwrap();
        assert_eq!(run.len(), 2);
        assert!(run.iter().all(|e| e.folder_hash() == folders[0].hash));
    }

    #[test]
    fn a_folder_row_pointing_outside_the_entry_segment_yields_no_run() {
        // The row is nonsense, but the container still opens: judging it is the inspector's job.
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.path("exd/root.exl", packed(0, 0x80))
            .folders(vec![FolderRow {
                hash: 1,
                entries_offset: 0,
                entries_size: 16,
            }]);
        let index = Index::parse(&b.bytes()).unwrap();
        assert!(index.folder_entries(&index.folders()[0]).is_none());
    }

    #[test]
    fn a_colliding_key_resolves_through_the_collision_table() {
        // Two paths sharing a key: the entry itself carries only the collision bit, and each path's
        // location lives in a record beside the literal path.
        let mut b = IndexBuilder::new(IndexKind::Index2);
        let key = u64::from(hash_path("chara/one.mdl").full);
        b.entry(key, 1)
            .collision(key, packed(1, 0x1000), 0, "chara/one.mdl")
            .collision(key, packed(2, 0x2000), 1, "chara/two.mdl");
        let index = Index::parse(&b.bytes()).unwrap();

        assert_eq!(index.collisions().len(), 2);
        assert!(index.lookup(key).unwrap().is_collision());
        assert_eq!(index.lookup(key).unwrap().location(), None);
        assert_eq!(
            index.resolve("chara/one.mdl").unwrap(),
            Some(DataLocation {
                dat: 1,
                offset: 0x1000
            })
        );
    }

    #[test]
    fn a_collision_the_table_cannot_spell_is_reported_rather_than_guessed() {
        let mut b = IndexBuilder::new(IndexKind::Index2);
        let key = u64::from(hash_path("chara/one.mdl").full);
        b.entry(key, 1)
            .collision(key, packed(2, 0x2000), 0, "chara/two.mdl");
        let index = Index::parse(&b.bytes()).unwrap();
        match index.resolve("chara/one.mdl") {
            Err(Error::SynonymUnresolved { key: reported }) => {
                assert_eq!(reported, format!("{key:#018x}"));
            }
            other => panic!("expected SynonymUnresolved, got {other:?}"),
        }
    }

    #[test]
    fn a_collision_record_spelling_the_path_in_another_case_still_matches() {
        let mut b = IndexBuilder::new(IndexKind::Index2);
        let key = u64::from(hash_path("chara/one.mdl").full);
        b.entry(key, 1)
            .collision(key, packed(1, 0x1000), 0, "CHARA/One.MDL");
        let index = Index::parse(&b.bytes()).unwrap();
        assert!(index.resolve("chara/one.mdl").unwrap().is_some());
    }

    #[test]
    fn an_empty_collision_table_is_just_its_terminator() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.path("exd/root.exl", packed(0, 0x80));
        let index = Index::parse(&b.bytes()).unwrap();
        assert!(index.collisions().is_empty());
        assert_eq!(
            index.header().collision_segment().size,
            COLLISION_RECORD_LEN as u32
        );
    }

    #[test]
    fn a_folder_row_that_does_not_land_on_entry_boundaries_yields_no_run() {
        // The row's extent is in bytes; a start or a length that is not a whole number of entries
        // describes no run of entries at all, however plausible the numbers look.
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.path("exd/root.exl", packed(0, 0x80))
            .path("exd/item.exh", packed(0, 0x100));
        let base = b.bytes();
        let entry_base = Index::parse(&base).unwrap().header().entry_segment().offset;

        for row in [
            FolderRow {
                hash: 1,
                entries_offset: entry_base + 8,
                entries_size: 16,
            },
            FolderRow {
                hash: 1,
                entries_offset: entry_base,
                entries_size: 24,
            },
        ] {
            let mut b = IndexBuilder::new(IndexKind::Index1);
            b.path("exd/root.exl", packed(0, 0x80))
                .path("exd/item.exh", packed(0, 0x100))
                .folders(vec![row]);
            let index = Index::parse(&b.bytes()).unwrap();
            assert!(
                index.folder_entries(&index.folders()[0]).is_none(),
                "{row:?}"
            );
        }
    }

    #[test]
    fn a_folder_table_on_a_second_form_container_names_no_run() {
        // An `.index2`'s entries are 8 bytes, so a folder row's byte extent would name a real but
        // wrong run of them. No real `.index2` carries a folder table; a rewritten one might.
        let mut b = IndexBuilder::new(IndexKind::Index2);
        b.path("exd/root.exl", packed(0, 0x80))
            .path("exd/item.exh", packed(0, 0x100))
            .folders(vec![FolderRow {
                hash: 1,
                entries_offset: COMMON_HEADER_LEN as u32 + INDEX_HEADER_LEN,
                entries_size: 16,
            }]);
        let index = Index::parse(&b.bytes()).unwrap();
        assert_eq!(index.folders().len(), 1);
        assert!(index.folder_entries(&index.folders()[0]).is_none());
    }

    #[test]
    fn the_collision_table_ends_at_its_terminator() {
        // Records past the terminator are not the table. Reading them would resurrect whatever a
        // shrinking rewrite left behind in the segment's tail.
        let mut b = IndexBuilder::new(IndexKind::Index2);
        let key = u64::from(hash_path("chara/one.mdl").full);
        b.entry(key, 1)
            .collision(key, packed(1, 0x1000), 0, "chara/one.mdl")
            .collision(key, packed(2, 0x2000), 1, "chara/two.mdl")
            .collision(COLLISION_TERMINATOR, 0, u32::MAX, "")
            .collision(key, packed(3, 0x3000), 2, "chara/three.mdl");
        let index = Index::parse(&b.bytes()).unwrap();
        assert_eq!(index.collisions().len(), 2);
        assert!(
            index
                .collisions()
                .iter()
                .all(|c| c.path != "chara/three.mdl")
        );
    }

    #[test]
    fn an_index2_collision_table_ends_at_a_terminator_in_its_key_width() {
        // An `.index2` key is 32 bits in the record's 8-byte field, and real archives spell the
        // sentinel both ways. Read against the filled form alone, the narrow one parses as a record
        // keyed `0xFFFF_FFFF` whose zero location word decodes to the start of dat 0: its own header.
        let key = u64::from(hash_path("chara/one.mdl").full);
        for narrow in [false, true] {
            let mut empty = IndexBuilder::new(IndexKind::Index2);
            empty.path("exd/root.exl", packed(0, 0x80));
            let mut shared = IndexBuilder::new(IndexKind::Index2);
            shared
                .entry(key, 1)
                .collision(key, packed(1, 0x1000), 0, "chara/one.mdl")
                .collision(key, packed(2, 0x2000), 1, "chara/two.mdl");
            if narrow {
                empty.terminator(Terminator::Narrow);
                shared.terminator(Terminator::Narrow);
            }

            let index = Index::parse(&empty.bytes()).unwrap();
            assert!(index.collisions().is_empty(), "narrow terminator: {narrow}");
            assert_eq!(
                index.header().collision_segment().size,
                COLLISION_RECORD_LEN as u32,
                "narrow terminator: {narrow}"
            );

            let index = Index::parse(&shared.bytes()).unwrap();
            assert_eq!(index.collisions().len(), 2, "narrow terminator: {narrow}");
            assert_eq!(
                index.resolve("chara/one.mdl").unwrap(),
                Some(DataLocation {
                    dat: 1,
                    offset: 0x1000
                }),
                "narrow terminator: {narrow}"
            );
        }
    }

    #[test]
    fn an_index_collision_table_reads_a_key_that_is_all_ones_in_one_half() {
        // An `.index` key is the folder hash over the file hash, so `0x0000_0000_FFFF_FFFF` names
        // folder 0's file `0xFFFF_FFFF` and `0xFFFF_FFFF_0000_0000` folder `0xFFFF_FFFF`'s file 0.
        // Both are records the table holds: only a key filling the whole field ends it.
        let low = u64::from(u32::MAX);
        let high = low << 32;
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.entry(low, 1)
            .entry(high, 1)
            .collision(low, packed(1, 0x1000), 0, "chara/one.mdl")
            .collision(high, packed(2, 0x2000), 0, "chara/two.mdl");
        let index = Index::parse(&b.bytes()).unwrap();
        assert_eq!(index.collisions().len(), 2);
        assert_eq!(index.collisions()[0].key, low);
        assert_eq!(index.collisions()[1].key, high);
    }

    #[test]
    fn a_collision_record_that_is_itself_a_placeholder_is_unresolved() {
        // Decoding it would answer with offset zero, which is the dat file's own header rather than
        // any file in it.
        let mut b = IndexBuilder::new(IndexKind::Index2);
        let key = u64::from(hash_path("chara/one.mdl").full);
        b.entry(key, 1).collision(key, 1, 0, "chara/one.mdl");
        let index = Index::parse(&b.bytes()).unwrap();
        assert_eq!(index.collisions()[0].location(), None);
        assert!(matches!(
            index.resolve("chara/one.mdl"),
            Err(Error::SynonymUnresolved { .. })
        ));
    }

    #[test]
    fn a_file_over_the_size_cap_is_refused_before_it_is_parsed() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.path("exd/root.exl", packed(0, 0x80));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("0a0000.win32.index");
        std::fs::write(&path, b.bytes()).unwrap();

        let tight = IndexLimits { max_index_bytes: 8 };
        assert!(matches!(
            Index::open_with_limits(&path, &tight),
            Err(Error::LimitExceeded)
        ));
        assert!(Index::open(&path).is_ok());
    }

    #[test]
    fn a_source_that_understates_its_length_is_still_capped_at_what_it_produced() {
        // A character device or a pipe reports a length of zero; the cap has to be enforced on the
        // bytes that actually arrive, not on what the directory entry claimed.
        let tight = IndexLimits {
            max_index_bytes: 4096,
        };
        let devices = ["/dev/zero", "/dev/urandom"];
        let Some(device) = devices.iter().find(|p| Path::new(p).exists()) else {
            return; // no such device on this host; the hermetic suite has nothing to prove here
        };
        assert!(matches!(
            Index::open_with_limits(device, &tight),
            Err(Error::LimitExceeded)
        ));
    }

    #[test]
    fn a_declared_segment_running_past_the_end_is_refused_even_when_nothing_reads_it() {
        // The third segment is not interpreted, but an inspector is handed its extent, so it has to be
        // an extent that exists.
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.path("exd/root.exl", packed(0, 0x80)).unclassified(64);
        let mut bytes = b.bytes();
        let declared = COMMON_HEADER_LEN + 0x9C + 4;
        bytes[declared..declared + 4].copy_from_slice(&bytes::write_u32_le(0xFFFF));
        assert!(matches!(Index::parse(&bytes), Err(Error::Truncated { .. })));
    }

    #[test]
    fn a_location_word_decodes_its_dat_and_its_eight_byte_offset() {
        // Byte-for-byte pin of the packing: bit 0 is the collision flag, bits 1-3 the dat file, and
        // the rest an offset in 8-byte units. Read without the shift, dat 5 would look like dat 42.
        let entry = IndexEntry {
            key: 0,
            packed: 0x0C27_9E2A,
        };
        assert!(!entry.is_collision());
        assert_eq!(
            entry.location(),
            Some(DataLocation {
                dat: 5,
                offset: 1_631_383_808
            })
        );
        assert_eq!(packed(5, 1_631_383_808), 0x0C27_9E2A);
    }

    #[test]
    fn an_index_key_is_the_folder_hash_over_the_file_hash() {
        let hash = hash_path("common/font/font1.tex");
        let entry = IndexEntry {
            key: hash.key(),
            packed: 0,
        };
        assert_eq!(entry.folder_hash(), hash.folder);
        assert_eq!(entry.file_hash(), hash.file);
    }

    #[test]
    fn the_header_records_a_nonstandard_size_and_version_verbatim() {
        // Same posture as the common header: recorded, never rejected, so the inspector can judge.
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.header_size(0x800).version(7).path("exd/root.exl", 0);
        let index = Index::parse(&b.bytes()).unwrap();
        assert_eq!(index.header().header_size, 0x800);
        assert_eq!(index.header().version, 7);
    }

    #[test]
    fn a_segment_sha1_is_carried_verbatim() {
        let sha1 = [0xAB; 20];
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.segment_sha1(0, sha1).path("exd/root.exl", 0);
        let index = Index::parse(&b.bytes()).unwrap();
        assert_eq!(index.header().entry_segment().sha1, sha1);
    }

    #[test]
    fn the_unclassified_segment_is_described_but_not_interpreted() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.path("exd/root.exl", 0).unclassified(64);
        let index = Index::parse(&b.bytes()).unwrap();
        assert_eq!(index.header().unclassified_segment().size, 64);
        assert!(!index.header().unclassified_segment().is_empty());
    }

    // --- hostile input: every fault is a typed error at an offset, never a panic ---

    #[test]
    fn a_data_container_is_not_an_index() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.container_kind(1).path("exd/root.exl", 0);
        match Index::parse(&b.bytes()) {
            Err(Error::IndexCorrupt { offset, detail }) => {
                assert_eq!(offset, 0x14);
                assert_eq!(detail, "not an index container");
            }
            other => panic!("expected IndexCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_index_kind_is_corrupt_at_its_own_offset() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.kind_word(9).path("exd/root.exl", 0);
        match Index::parse(&b.bytes()) {
            Err(Error::IndexCorrupt { offset, detail }) => {
                assert_eq!(offset, 0x400 + 0x12C);
                assert_eq!(detail, "unknown index kind");
            }
            other => panic!("expected IndexCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn a_container_cut_short_of_its_index_header_is_truncated() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.path("exd/root.exl", 0);
        let bytes = b.bytes();
        for cut in [COMMON_HEADER_LEN, COMMON_HEADER_LEN + 0x100] {
            match Index::parse(&bytes[..cut]) {
                Err(Error::Truncated { offset, .. }) => assert!(offset >= COMMON_HEADER_LEN as u64),
                other => panic!("expected Truncated at {cut}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_segment_running_past_the_end_of_the_file_is_truncated() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.path("exd/root.exl", 0);
        let bytes = b.bytes();
        // Drop the tail so the declared folder segment no longer fits.
        let short = &bytes[..bytes.len() - 8];
        assert!(matches!(Index::parse(short), Err(Error::Truncated { .. })));
    }

    #[test]
    fn an_entry_segment_that_is_not_a_whole_number_of_entries_is_corrupt() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.path("exd/root.exl", 0);
        let mut bytes = b.bytes();
        // Claim one byte more than the entries occupy, which is no longer a multiple of 16.
        let declared = COMMON_HEADER_LEN + 0x0C;
        bytes[declared..declared + 4].copy_from_slice(&bytes::write_u32_le(17));
        match Index::parse(&bytes) {
            Err(Error::IndexCorrupt { detail, .. }) => {
                assert_eq!(detail, "entry segment is not a whole number of entries");
            }
            other => panic!("expected IndexCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn an_unsorted_entry_table_is_still_looked_up_correctly() {
        // A rewritten container may not sort. The reader notices and scans rather than binary-
        // searching, which would silently miss entries the container really holds.
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.entry(300, packed(0, 0x180))
            .entry(100, packed(0, 0x80))
            .entry(200, packed(0, 0x100));
        let index = Index::parse(&b.bytes()).unwrap();
        assert!(!index.is_sorted());
        for key in [100, 200, 300] {
            assert_eq!(index.lookup(key).map(|e| e.key), Some(key));
        }
        assert_eq!(index.lookup(400), None);
    }

    #[test]
    fn a_duplicated_key_resolves_to_the_first_entry_in_file_order() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.entry(100, packed(0, 0x80))
            .entry(100, packed(1, 0x100))
            .entry(100, packed(2, 0x180))
            .entry(200, packed(0, 0x200));
        let index = Index::parse(&b.bytes()).unwrap();
        assert!(index.is_sorted());
        assert_eq!(index.lookup(100).unwrap().packed, packed(0, 0x80));
    }

    // A lookup must agree with a scan on every table, sorted or not, with or without repeats: the
    // binary search is an optimization and this is what says it never changes the answer. A fixture
    // cannot cover the shapes a rewritten container can take.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn a_lookup_agrees_with_a_linear_scan(
            keys in prop::collection::vec(0u64..64, 0..40),
            sorted in any::<bool>(),
        ) {
            let mut keys = keys;
            if sorted {
                keys.sort_unstable();
            }
            let mut b = IndexBuilder::new(IndexKind::Index1);
            for (i, key) in keys.iter().enumerate() {
                b.entry(*key, packed(0, (i as u64 + 1) * 128));
            }
            let index = Index::parse(&b.bytes()).map_err(|e| TestCaseError::fail(e.to_string()))?;
            for probe in 0u64..66 {
                let scanned = index.entries().iter().find(|e| e.key == probe);
                prop_assert_eq!(index.lookup(probe), scanned, "key {}", probe);
            }
        }
    }
}
