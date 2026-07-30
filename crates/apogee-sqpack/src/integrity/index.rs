//! The index container's checks: what an `.index`/`.index2` declares about itself against what it
//! holds.
//!
//! Pure over a byte slice, because the whole container is what the two header hashes and the four
//! segment hashes cover, and because the checks the reader deliberately drops (each entry's reserved
//! word, the collision segment's raw records and the position of its terminator, the two runs no hash
//! covers) live in bytes the parsed form no longer carries.
//!
//! The strongest check here is the one that ties a literal path to a hash: a collision record spells
//! its path in full, so re-hashing it must land on the key the record is filed under. It is vacuous on
//! a pristine `.index`, whose collision tables are all empty, and it is the only place in the crate
//! where a name and a hash can be compared at all.

use std::collections::BTreeMap;

use super::finding::{Sink, read_fault};
use crate::bytes;
use crate::container::COMMON_HEADER_LEN;
use crate::hash::hash_path;
use crate::index::{
    COLLISION_PATH_AT, COLLISION_RECORD_LEN, DATA_FILE_COUNT_AT, FOLDER_ROW_LEN, INDEX_HEADER_LEN,
    INDEX_HEADER_OFFSET, INDEX_KIND_AT, INDEX1_ENTRY_LEN, Index, IndexKind, SEGMENT_DESCRIPTOR_AT,
    SegmentDescriptor, UNCLASSIFIED_RECORD_LEN,
};
use crate::integrity::{
    COMMON_HEADER_SIZE_AT, COMMON_VERSION_AT, ContainerId, ContainerRef, ContainerReport, Defect,
    FORMAT_VERSION, Finding, HeaderWord, Site, SweepOptions, Totals, UNCLAIMED_DIGEST,
    check_self_hashes, check_uncovered_runs, sha1, u32_at,
};

/// Where the first segment starts, and so where the segment table has to begin tiling.
const FIRST_SEGMENT_OFFSET: u32 = COMMON_HEADER_LEN as u32 + INDEX_HEADER_LEN;

/// The reserved word inside an `.index` entry, which the reader drops.
const ENTRY_PAD_AT: usize = 12;

/// The reserved word inside a folder row, which the reader drops.
const FOLDER_ROW_PAD_AT: usize = 12;

/// The location word's collision flag: bit 0, and nothing else, on a real placeholder.
const COLLISION_FLAG: u32 = 1;

/// What the archive's directory says, so a container check judges what the container declares against
/// it without touching a filesystem itself.
#[derive(Debug, Clone, Copy)]
pub struct IndexFacts<'a> {
    /// Which container the findings are about.
    pub container: ContainerRef,
    /// The form the file name spells, so a declared kind that disagrees is a finding.
    pub named: IndexKind,
    /// The `.dat{n}` numbers sitting beside the archive, ascending.
    pub dats: &'a [u8],
}

/// One location an index named and the key that named it. Field order is the sort order the dat walk
/// and the form comparison both need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Located {
    /// Which `.dat{n}` of the archive holds the bytes.
    pub dat: u8,
    /// The byte offset within that data file.
    pub offset: u64,
    /// The index key that named it.
    pub key: u64,
}

/// What inspecting one index container produced.
#[derive(Debug, Clone)]
pub struct IndexInspection {
    /// The findings and what the checks accounted for.
    pub report: ContainerReport,
    /// The parsed container, handed back so a caller that goes on to read the archive itself need not
    /// parse it twice. `None` exactly when the report carries a [`Defect::ContainerUnreadable`]. It is
    /// the largest thing an inspection holds, and everything above is derived from it already, so a
    /// caller working through a whole install drops these as it goes.
    pub index: Option<Index>,
    /// Every location the container names, entries and collision records together, ascending by
    /// `(dat, offset, key)`. Empty when the container did not parse.
    pub locations: Vec<Located>,
}

/// Inspect one index container from its bytes.
///
/// Infallible: a container that will not parse is the finding, not a reason to refuse an answer.
#[must_use]
pub fn inspect_index(bytes: &[u8], facts: &IndexFacts<'_>, opts: &SweepOptions) -> IndexInspection {
    let mut sink = Sink::new(facts.container, opts.max_defects_per_container);
    let mut totals = Totals {
        index_files: 1,
        index_bytes: bytes.len() as u64,
        ..Totals::default()
    };

    let index = match Index::parse(bytes) {
        Ok(index) => index,
        Err(error) => {
            let (fault, detail, offset) = read_fault(&error);
            sink.push_on(offset, Defect::ContainerUnreadable { fault, detail });
            totals.containers_unreadable = 1;
            return IndexInspection {
                report: sink.finish(totals),
                index: None,
                locations: Vec::new(),
            };
        }
    };

    check_header_words(&index, facts, &mut sink);
    check_self_hashes(bytes, &mut sink, &mut totals);
    check_segment_hashes(bytes, &index, &mut sink, &mut totals);
    check_uncovered_runs(bytes, &mut sink);
    check_segments(bytes, &index, &mut sink);
    let flagged = check_entries(bytes, &index, facts, &mut sink);
    check_collisions(bytes, &index, &flagged, &mut sink);
    check_folders(bytes, &index, &mut sink);

    let locations = locations_of(&index);
    totals.entries = index.entries().len() as u64;
    totals.collision_records = index.collisions().len() as u64;
    totals.locations = locations.len() as u64;
    IndexInspection {
        report: sink.finish(totals),
        index: Some(index),
        locations,
    }
}

/// Check that the two forms of one archive name the same multiset of `(dat, offset)` locations.
///
/// Keys are deliberately not compared: an `.index2`'s 32-bit key folds colliding paths into one
/// placeholder plus a record apiece, so its entry count is lower than its `.index`'s on several
/// archives of a full install while both still name the same locations.
///
/// `first` is the `.index`'s locations and `second` the `.index2`'s, both sorted the way
/// [`IndexInspection::locations`] is. Findings are filed against whichever form holds the location the
/// other lacks, derived from `archive` with [`ContainerRef::with_file`]. At most
/// `opts.max_defects_per_container` are carried; the walk still runs to the end of both slices, so what
/// it declined to carry is counted in [`Totals::defects_suppressed`] rather than left to be guessed at
/// from how many it returned.
#[must_use]
pub fn compare_index_forms(
    first: &[Located],
    second: &[Located],
    archive: ContainerRef,
    opts: &SweepOptions,
) -> ContainerReport {
    let mut out = Vec::new();
    let mut suppressed = 0u64;
    let mut only_in = |located: &Located, kind: IndexKind, out: &mut Vec<Finding>| {
        if out.len() >= opts.max_defects_per_container {
            suppressed += 1;
            return;
        }
        out.push(Finding {
            site: Site {
                container: archive.with_file(ContainerId::Index(kind)),
                offset: None,
                key: Some(located.key),
            },
            defect: Defect::FormsDisagree {
                only_in: kind,
                dat: located.dat,
                offset: located.offset,
            },
        });
    };

    // A merge walk over the two sorted slices, comparing where the bytes are and not what named them.
    // Equal locations are consumed pairwise, so a location one form holds twice is reported.
    let (mut i, mut j) = (0, 0);
    loop {
        match (first.get(i), second.get(j)) {
            (Some(a), Some(b)) => match (a.dat, a.offset).cmp(&(b.dat, b.offset)) {
                std::cmp::Ordering::Less => {
                    only_in(a, IndexKind::Index1, &mut out);
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    only_in(b, IndexKind::Index2, &mut out);
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    i += 1;
                    j += 1;
                }
            },
            (Some(a), None) => {
                only_in(a, IndexKind::Index1, &mut out);
                i += 1;
            }
            (None, Some(b)) => {
                only_in(b, IndexKind::Index2, &mut out);
                j += 1;
            }
            (None, None) => break,
        }
    }
    out.sort_unstable();
    ContainerReport {
        findings: out,
        totals: Totals {
            defects_suppressed: suppressed,
            ..Totals::default()
        },
        truncated: suppressed > 0,
    }
}

/// The words every container of this kind spells the same. The magic, the platform byte and the
/// container type are what [`Index::parse`] already refused, so what is left here is the four words it
/// records rather than judges, and the form the file name promised.
fn check_header_words(index: &Index, facts: &IndexFacts<'_>, sink: &mut Sink) {
    let common = index.common_header();
    if common.header_size != COMMON_HEADER_LEN as u32 {
        sink.push_at(
            COMMON_HEADER_SIZE_AT,
            Defect::HeaderWord {
                word: HeaderWord::CommonHeaderSize,
                declared: common.header_size,
                expected: COMMON_HEADER_LEN as u32,
            },
        );
    }
    if common.version != FORMAT_VERSION {
        sink.push_at(
            COMMON_VERSION_AT,
            Defect::HeaderWord {
                word: HeaderWord::CommonVersion,
                declared: common.version,
                expected: FORMAT_VERSION,
            },
        );
    }

    let header = index.header();
    if header.header_size != INDEX_HEADER_LEN {
        sink.push_at(
            INDEX_HEADER_OFFSET,
            Defect::HeaderWord {
                word: HeaderWord::SecondHeaderSize,
                declared: header.header_size,
                expected: INDEX_HEADER_LEN,
            },
        );
    }
    if header.version != FORMAT_VERSION {
        sink.push_at(
            INDEX_HEADER_OFFSET + 4,
            Defect::HeaderWord {
                word: HeaderWord::SecondVersion,
                declared: header.version,
                expected: FORMAT_VERSION,
            },
        );
    }
    if header.kind != facts.named {
        sink.push_at(
            INDEX_KIND_AT,
            Defect::IndexKindDisagreesWithName {
                declared: header.kind,
                named: facts.named,
            },
        );
    }
}

/// The four digests an index container declares beyond its two headers': one per non-empty segment
/// over that segment's bytes. A field of all zeros claims nothing and is counted instead.
fn check_segment_hashes(bytes: &[u8], index: &Index, sink: &mut Sink, totals: &mut Totals) {
    for (n, descriptor) in index.header().segments.iter().enumerate() {
        let Some(body) = segment_bytes(bytes, descriptor) else {
            continue;
        };
        if descriptor.sha1 == UNCLAIMED_DIGEST {
            totals.unclaimed_hash_fields += 1;
            continue;
        }
        let computed = sha1(body);
        totals.bytes_hashed += body.len() as u64;
        if computed != descriptor.sha1 {
            sink.push_at(
                u64::from(descriptor.offset),
                Defect::SegmentHashMismatch {
                    segment: n as u8,
                    len: descriptor.size,
                    declared: descriptor.sha1,
                    computed,
                },
            );
        }
    }
}

/// The segment table: the non-empty segments tile the file from the first segment offset to the end,
/// each is a whole number of its records, and neither form carries the other's segments.
///
/// Emptiness is `size == 0` alone. An empty descriptor's declared offset is never read, because real
/// containers leave it at the write cursor, at zero, or at a stale position from before the segment
/// was emptied, and all three are correct.
fn check_segments(bytes: &[u8], index: &Index, sink: &mut Sink) {
    let header = index.header();
    let record_lens = [
        header.kind.entry_len() as u32,
        COLLISION_RECORD_LEN as u32,
        UNCLASSIFIED_RECORD_LEN as u32,
        FOLDER_ROW_LEN as u32,
    ];

    let mut used: Vec<(u8, u32, u32)> = Vec::new();
    for (n, descriptor) in header.segments.iter().enumerate() {
        if descriptor.is_empty() {
            continue;
        }
        used.push((n as u8, descriptor.offset, descriptor.size));
        // Only the third segment can reach this: the reader refuses the other three outright, and
        // that refusal is already a `ContainerUnreadable`.
        if !descriptor.size.is_multiple_of(record_lens[n]) {
            sink.push_at(
                SEGMENT_DESCRIPTOR_AT[n],
                Defect::SegmentRagged {
                    segment: n as u8,
                    len: descriptor.size,
                    record_len: record_lens[n],
                },
            );
        }
    }

    used.sort_unstable_by_key(|&(_, offset, _)| offset);
    let mut expected = FIRST_SEGMENT_OFFSET;
    for &(n, offset, size) in &used {
        if offset != expected {
            sink.push_at(
                SEGMENT_DESCRIPTOR_AT[n as usize],
                Defect::SegmentsDoNotTile {
                    segment: n,
                    declared: offset,
                    expected,
                },
            );
        }
        // Carrying on from where this segment actually is keeps one displaced segment to one finding
        // rather than reporting every segment after it.
        expected = offset.saturating_add(size);
    }
    if bytes.len() as u64 > u64::from(expected) {
        sink.push_at(
            u64::from(expected),
            Defect::TrailingBytes {
                len: bytes.len() as u64 - u64::from(expected),
            },
        );
    }

    let entries = header.entry_segment();
    let unclassified = header.unclassified_segment();
    let folders = header.folder_segment();
    match header.kind {
        IndexKind::Index2 => {
            if !unclassified.is_empty() {
                sink.push_at(
                    SEGMENT_DESCRIPTOR_AT[2],
                    Defect::UnclassifiedSegmentOnSecondForm {
                        len: unclassified.size,
                    },
                );
            }
            if !folders.is_empty() {
                sink.push_at(
                    SEGMENT_DESCRIPTOR_AT[3],
                    Defect::FolderTableOnSecondForm {
                        rows: folders.size / FOLDER_ROW_LEN as u32,
                    },
                );
            }
        }
        IndexKind::Index1 => {
            // A folder table is present in exactly the `.index` files that hold entries.
            if !entries.is_empty() && folders.is_empty() {
                sink.push_at(
                    SEGMENT_DESCRIPTOR_AT[3],
                    Defect::FolderTableMissing {
                        entries: entries.size / header.kind.entry_len() as u32,
                    },
                );
            }
        }
    }
}

/// The entry table, walked against the raw segment bytes beside the parsed entries because the
/// reserved word is the one field the reader drops. Answers with the keys that are collision
/// placeholders, which the collision table is then cross-checked against.
fn check_entries(
    bytes: &[u8],
    index: &Index,
    facts: &IndexFacts<'_>,
    sink: &mut Sink,
) -> BTreeMap<u64, u64> {
    let header = index.header();
    let base = header.entry_segment().offset as usize;
    let stride = header.kind.entry_len();
    let mut flagged = BTreeMap::new();
    let mut previous: Option<u64> = None;

    for (i, entry) in index.entries().iter().enumerate() {
        let at = base + i * stride;
        let offset = at as u64;
        match previous {
            Some(p) if entry.key < p => sink.push_keyed(
                offset,
                entry.key,
                Defect::EntryKeysNotAscending { previous: p },
            ),
            Some(p) if entry.key == p => {
                sink.push_keyed(offset, entry.key, Defect::DuplicateEntryKey);
            }
            _ => {}
        }
        previous = Some(entry.key);

        if header.kind == IndexKind::Index1
            && let Some(pad) = u32_at(bytes, at + ENTRY_PAD_AT)
            && pad != 0
        {
            sink.push_keyed(offset, entry.key, Defect::EntryPadNotZero { pad });
        }

        if entry.is_collision() {
            if entry.packed != COLLISION_FLAG {
                sink.push_keyed(
                    offset,
                    entry.key,
                    Defect::CollisionFlagNotBare {
                        packed: entry.packed,
                    },
                );
            }
            flagged.insert(entry.key, offset);
        } else if let Some(location) = entry.location()
            && u32::from(location.dat) >= header.data_file_count
        {
            sink.push_keyed(
                offset,
                entry.key,
                Defect::EntryDatOutOfRange {
                    dat: location.dat,
                    declared: header.data_file_count,
                },
            );
        }
    }

    if header.data_file_count != facts.dats.len() as u32 {
        sink.push_at(
            DATA_FILE_COUNT_AT,
            Defect::DeclaredDatCount {
                declared: header.data_file_count,
                present: facts.dats.len() as u32,
            },
        );
    }
    flagged
}

/// One record of the collision table as the bytes spell it, which is more than the reader keeps: the
/// record's own position, and the conflict index it drops once a table is parsed.
struct RawRecord {
    at: u64,
    key: u64,
    conflict_index: u32,
}

/// The collision table, walked over the raw segment bytes rather than the parsed records, because the
/// terminator's position, the records past it and the path field's tail are all things the reader
/// drops.
fn check_collisions(bytes: &[u8], index: &Index, flagged: &BTreeMap<u64, u64>, sink: &mut Sink) {
    let header = index.header();
    let descriptor = header.collision_segment();
    let body = segment_bytes(bytes, descriptor).unwrap_or_default();
    let base = u64::from(descriptor.offset);

    let mut records: Vec<RawRecord> = Vec::new();
    let mut terminated = false;
    for (i, record) in body.chunks_exact(COLLISION_RECORD_LEN).enumerate() {
        let consumed = (i + 1) * COLLISION_RECORD_LEN;
        let at = base + (i * COLLISION_RECORD_LEN) as u64;
        let key = u64_at(record, 0).unwrap_or_default();
        if header.kind.terminates_collisions(key) {
            terminated = true;
            // Whatever sits past the terminator is not the table at all, so where it starts is the
            // whole finding: reading those records would resurrect what a shrinking rewrite left.
            if consumed < body.len() {
                sink.push_at(
                    at + COLLISION_RECORD_LEN as u64,
                    Defect::CollisionRecordAfterTerminator,
                );
            }
            break;
        }
        let packed = u32_at(record, 8).unwrap_or_default();
        check_collision_path(
            record.get(COLLISION_PATH_AT..).unwrap_or_default(),
            header.kind,
            key,
            at,
            sink,
        );
        if packed & COLLISION_FLAG != 0 {
            sink.push_keyed(at, key, Defect::CollisionRecordIsPlaceholder { packed });
        }
        records.push(RawRecord {
            at,
            key,
            conflict_index: u32_at(record, 12).unwrap_or_default(),
        });
    }
    if !terminated {
        // An empty segment's declared offset is not to be read, so the descriptor's own position is
        // where an absent table is reported from.
        let at = if descriptor.is_empty() {
            SEGMENT_DESCRIPTOR_AT[1]
        } else {
            base
        };
        sink.push_at(
            at,
            Defect::CollisionTableUnterminated {
                records: records.len() as u32,
            },
        );
    }

    let mut by_key: BTreeMap<u64, Vec<&RawRecord>> = BTreeMap::new();
    for record in &records {
        by_key.entry(record.key).or_default().push(record);
    }
    for (key, group) in &by_key {
        check_conflict_indexes(*key, group, sink);
        if !flagged.contains_key(key)
            && let Some(first) = group.first()
        {
            sink.push_keyed(first.at, *key, Defect::CollisionRecordWithoutFlaggedEntry);
        }
    }
    for (key, at) in flagged {
        // "At least two", not "exactly two": every real collision is a pair, but that is a property
        // of the collisions that happened rather than of the format.
        let records = by_key.get(key).map_or(0, Vec::len);
        if records < 2 {
            sink.push_keyed(
                *at,
                *key,
                Defect::FlaggedEntryWithoutRecords {
                    records: records as u32,
                },
            );
        }
    }
}

/// The records under one key carry each of `0..n` exactly once. Reported at the first record in table
/// order whose index is out of range or already taken, so one displaced word is one finding.
fn check_conflict_indexes(key: u64, group: &[&RawRecord], sink: &mut Sink) {
    let mut taken = vec![false; group.len()];
    for record in group {
        match usize::try_from(record.conflict_index)
            .ok()
            .and_then(|i| taken.get_mut(i))
        {
            Some(slot) if !*slot => *slot = true,
            _ => {
                sink.push_keyed(
                    record.at,
                    key,
                    Defect::CollisionConflictIndexUnexpected {
                        conflict_index: record.conflict_index,
                        records: group.len() as u32,
                    },
                );
                return;
            }
        }
    }
}

/// A collision record's path field: NUL-terminated inside the field, printable ASCII up to the NUL,
/// and hashing to the key the record is filed under.
///
/// The three checks are a chain that stops at the first fault: bytes that are not a terminated ASCII
/// path are not a path, so hashing them against the key would only say the same thing twice. The
/// field's tail past the NUL is deliberately not checked, because no real record zeroes it: it carries
/// whatever longer path was written there before.
fn check_collision_path(field: &[u8], kind: IndexKind, key: u64, at: u64, sink: &mut Sink) {
    let Some(nul) = field.iter().position(|&b| b == 0) else {
        sink.push_keyed(at, key, Defect::CollisionPathUnterminated);
        return;
    };
    let path = field.get(..nul).unwrap_or_default();
    if let Some(i) = path
        .iter()
        .position(|&b| !b.is_ascii_graphic() && b != b' ')
    {
        sink.push_keyed(at, key, Defect::CollisionPathNotAscii { at: i as u32 });
        return;
    }
    // Printable ASCII is valid UTF-8, so this holds; a lossy conversion would hash other bytes.
    let Ok(text) = std::str::from_utf8(path) else {
        return;
    };
    let hash = hash_path(text);
    let hashes_to = match kind {
        IndexKind::Index1 => hash.key(),
        IndexKind::Index2 => u64::from(hash.full),
    };
    if hashes_to != key {
        sink.push_keyed(at, key, Defect::CollisionPathKeyMismatch { hashes_to });
    }
}

/// The folder table, `.index` only: rows ascending by hash, reserved words zero, runs tiling the entry
/// segment exactly, and every entry in a run carrying that run's folder hash.
fn check_folders(bytes: &[u8], index: &Index, sink: &mut Sink) {
    let header = index.header();
    if header.kind != IndexKind::Index1 || index.folders().is_empty() {
        return;
    }
    let base = header.folder_segment().offset as usize;
    let entry_base = header.entry_segment().offset;
    let entry_end = entry_base.saturating_add(header.entry_segment().size);
    let mut previous: Option<u32> = None;
    let mut expected = entry_base;
    let mut last_row_at = base as u64;

    for (i, row) in index.folders().iter().enumerate() {
        let at = base + i * FOLDER_ROW_LEN;
        let offset = at as u64;
        last_row_at = offset;
        if let Some(p) = previous
            && row.hash <= p
        {
            sink.push_at(
                offset,
                Defect::FolderRowsNotAscending {
                    hash: row.hash,
                    previous: p,
                },
            );
        }
        previous = Some(row.hash);
        if let Some(pad) = u32_at(bytes, at + FOLDER_ROW_PAD_AT)
            && pad != 0
        {
            sink.push_at(
                offset,
                Defect::FolderRowPadNotZero {
                    hash: row.hash,
                    pad,
                },
            );
        }
        let tiles = row.entries_offset == expected;
        if !tiles {
            sink.push_at(
                offset,
                Defect::FolderRowsDoNotTile {
                    declared: row.entries_offset,
                    expected,
                },
            );
        }
        expected = row.entries_offset.saturating_add(row.entries_size);

        // Only a run that starts where the previous one ended is this row's to speak for, and saying so
        // once per entry of a run the table does not own would repeat the tiling finding above. It is
        // also what keeps this walk inside the entry table's own length: rows that tile hold disjoint
        // runs of it, where nothing stops every row of a container naming the whole table and turning
        // one container's check into the product of its two segments.
        if tiles && let Some(run) = index.folder_entries(row) {
            let first =
                (row.entries_offset.saturating_sub(entry_base) / INDEX1_ENTRY_LEN as u32) as usize;
            for (j, entry) in run.iter().enumerate() {
                if entry.folder_hash() != row.hash {
                    let entry_at = entry_base as usize + (first + j) * INDEX1_ENTRY_LEN;
                    sink.push_keyed(
                        entry_at as u64,
                        entry.key,
                        Defect::FolderHashDisagreesWithEntry {
                            folder: row.hash,
                            entry_folder: entry.folder_hash(),
                        },
                    );
                }
            }
        }
    }

    if expected != entry_end {
        sink.push_at(
            last_row_at,
            Defect::FolderRowsDoNotTile {
                declared: expected,
                expected: entry_end,
            },
        );
    }
}

/// Every location the container names: each entry that is not a placeholder, plus each collision
/// record that carries a location of its own. Ascending by `(dat, offset, key)`, which is the order
/// the dat walk and the form comparison both read.
fn locations_of(index: &Index) -> Vec<Located> {
    let mut out = Vec::with_capacity(index.entries().len());
    for entry in index.entries() {
        if let Some(location) = entry.location() {
            out.push(Located {
                dat: location.dat,
                offset: location.offset,
                key: entry.key,
            });
        }
    }
    // The reader ends its collision walk at the same terminator this module's raw walk does, so these
    // are exactly the records the checks above judged.
    for record in index.collisions() {
        if let Some(location) = record.location() {
            out.push(Located {
                dat: location.dat,
                offset: location.offset,
                key: record.key,
            });
        }
    }
    out.sort_unstable();
    out
}

/// A declared segment's bytes, or `None` when the segment is empty or does not fit the file. Only the
/// latter is a fault, and [`Index::parse`] has already refused it.
fn segment_bytes<'a>(bytes: &'a [u8], descriptor: &SegmentDescriptor) -> Option<&'a [u8]> {
    if descriptor.is_empty() {
        return None;
    }
    let start = usize::try_from(descriptor.offset).ok()?;
    let len = usize::try_from(descriptor.size).ok()?;
    bytes.get(start..start.checked_add(len)?)
}

/// A little-endian `u64` at `at`, or `None` if the bytes do not reach.
fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at.checked_add(8)?)
        .and_then(|raw| <[u8; 8]>::try_from(raw).ok())
        .map(bytes::u64_le)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveId;
    use crate::game::Repo;
    use crate::index::build::{IndexBuilder, Terminator, packed};
    use crate::index::{FolderRow, SEGMENT_COUNT};
    use crate::integrity::{
        HeaderId, ReadFault, SELF_HASH_AT, SELF_HASH_LEN, Scope, Severity, digest_at,
    };
    use proptest::prelude::*;

    /// Two paths in one folder whose file-name hashes are equal, so an `.index` keys them the same and
    /// has to file both in its collision table. Their whole-path hashes differ, so an `.index2` keys
    /// them apart, which is the real shape: the second form folds collisions the first does not.
    ///
    /// Searched once and pinned rather than searched at test time. The hash is CRC-32 with the final
    /// inversion left off, which is affine, so a family of same-shaped paths never collides and a
    /// search over one never terminates; these came out of a search over random lengths.
    const SHARED_FILE_HASH: [&str; 2] = [
        "chara/monster/m0001/obj/body/b0001/model/1ki1h5.mdl",
        "chara/monster/m0001/obj/body/b0001/model/n7_vzit0l0y.mdl",
    ];

    /// Two paths whose whole-path hashes are equal, which is what an `.index2` is keyed by. Their
    /// file-name hashes differ, so an `.index` keys them apart. Pinned for the same reason.
    const SHARED_PATH_HASH: [&str; 2] = [
        "chara/monster/m0001/obj/body/b0001/model/59c3iwc.mdl",
        "chara/monster/m0001/obj/body/b0001/model/v6gpxc.mdl",
    ];

    /// The leftovers a real record carries in its path field after the path's terminating NUL: the
    /// field is never zeroed, so it holds whatever longer path was written there before.
    const PATH_TAIL: &[u8] = b"chara/monster/m0001/obj/body/b0001/model/was_longer.mdl";

    fn container(named: IndexKind) -> ContainerRef {
        ContainerRef::new(
            Repo::Base,
            ArchiveId::new(0x04, 0, 0),
            ContainerId::Index(named),
        )
    }

    /// The key the two paths of [`SHARED_FILE_HASH`] share in an `.index`.
    fn shared_index1_key() -> u64 {
        hash_path(SHARED_FILE_HASH[0]).key()
    }

    /// The key the two paths of [`SHARED_PATH_HASH`] share in an `.index2`.
    fn shared_index2_key() -> u64 {
        u64::from(hash_path(SHARED_PATH_HASH[0]).full)
    }

    /// A byte-faithful `.index` over two data files: entries in three folders, a real colliding pair
    /// behind a placeholder, path fields carrying leftovers, and a third segment nothing interprets.
    fn clean_index1() -> IndexBuilder {
        let key = shared_index1_key();
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .path("exd/root.exl", packed(0, 0x800))
            .path("common/font/font1.tex", packed(0, 0x1000))
            .path("common/font/font2.tex", packed(1, 0x800))
            .entry(key, 1)
            .collision(key, packed(1, 0x1000), 0, SHARED_FILE_HASH[0])
            .collision(key, packed(1, 0x1800), 1, SHARED_FILE_HASH[1])
            .collision_path_tail(PATH_TAIL)
            .unclassified(32)
            .sort_entries();
        b
    }

    /// The same over an `.index2`, whose collision is the pair the whole-path hash folds.
    fn clean_index2() -> IndexBuilder {
        let key = shared_index2_key();
        let mut b = IndexBuilder::new(IndexKind::Index2);
        b.data_file_count(2)
            .path("exd/root.exl", packed(0, 0x800))
            .path("common/font/font1.tex", packed(0, 0x1000))
            .entry(key, 1)
            .collision(key, packed(1, 0x1000), 0, SHARED_PATH_HASH[0])
            .collision(key, packed(1, 0x1800), 1, SHARED_PATH_HASH[1])
            .collision_path_tail(PATH_TAIL)
            .sort_entries();
        b
    }

    fn inspect(bytes: &[u8], named: IndexKind, dats: &[u8]) -> IndexInspection {
        let facts = IndexFacts {
            container: container(named),
            named,
            dats,
        };
        inspect_index(bytes, &facts, &SweepOptions::default())
    }

    /// The findings a container yields under a two-dat archive.
    fn findings(bytes: &[u8], named: IndexKind) -> Vec<Finding> {
        inspect(bytes, named, &[0, 1]).report.findings
    }

    /// The one finding a mutation is expected to produce. An over-eager neighbouring check shows up
    /// here as a second finding, which is the point of asserting the count.
    fn only(bytes: &[u8], named: IndexKind) -> Finding {
        let found = findings(bytes, named);
        assert_eq!(found.len(), 1, "expected one finding, got {found:#?}");
        found[0]
    }

    /// Where the entry keyed `key` sits, so a test names a site without hardcoding the order the keys
    /// happened to sort into.
    fn entry_offset(bytes: &[u8], key: u64) -> u64 {
        let Ok(index) = Index::parse(bytes) else {
            return 0;
        };
        let position = index
            .entries()
            .iter()
            .position(|entry| entry.key == key)
            .unwrap_or_default();
        u64::from(index.header().entry_segment().offset)
            + (position * index.header().kind.entry_len()) as u64
    }

    /// Where the `n`th collision record sits.
    fn collision_offset(bytes: &[u8], n: usize) -> u64 {
        let Ok(index) = Index::parse(bytes) else {
            return 0;
        };
        u64::from(index.header().collision_segment().offset) + (n * COLLISION_RECORD_LEN) as u64
    }

    /// Where the `n`th folder row sits.
    fn folder_offset(bytes: &[u8], n: usize) -> u64 {
        let Ok(index) = Index::parse(bytes) else {
            return 0;
        };
        u64::from(index.header().folder_segment().offset) + (n * FOLDER_ROW_LEN) as u64
    }

    /// The folder table the clean `.index` derives, as a starting point for rewriting one row.
    fn clean_folder_rows() -> Vec<FolderRow> {
        Index::parse(&clean_index1().bytes())
            .map(|index| index.folders().to_vec())
            .unwrap_or_default()
    }

    // --- the gate: a coherent container produces nothing at all ---

    #[test]
    fn a_clean_container_of_each_form_yields_no_findings() {
        let bytes = clean_index1().bytes();
        let inspection = inspect(&bytes, IndexKind::Index1, &[0, 1]);
        assert!(
            inspection.report.findings.is_empty(),
            "{:#?}",
            inspection.report.findings
        );
        assert!(!inspection.report.truncated);
        let totals = inspection.report.totals;
        assert_eq!(totals.index_files, 1);
        assert_eq!(totals.index_bytes, bytes.len() as u64);
        assert_eq!(totals.entries, 4);
        assert_eq!(totals.collision_records, 2);
        // Three plain entries plus the two records the placeholder stands for.
        assert_eq!(totals.locations, 5);
        assert_eq!(inspection.locations.len(), 5);
        assert!(inspection.locations.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(totals.unclaimed_hash_fields, 0);

        let bytes = clean_index2().bytes();
        let inspection = inspect(&bytes, IndexKind::Index2, &[0, 1]);
        assert!(
            inspection.report.findings.is_empty(),
            "{:#?}",
            inspection.report.findings
        );
        assert_eq!(inspection.report.totals.entries, 3);
        assert_eq!(inspection.report.totals.collision_records, 2);
        assert_eq!(inspection.report.totals.locations, 4);
    }

    #[test]
    fn the_path_field_the_fixture_writes_really_does_carry_leftovers() {
        // The clean case is only worth anything if it exercises the shape it claims to: a record whose
        // path field is not zeroed past the NUL. Without this the tail knob could quietly do nothing.
        let bytes = clean_index1().bytes();
        let at = collision_offset(&bytes, 0) as usize + COLLISION_PATH_AT;
        let field = &bytes[at..at + COLLISION_RECORD_LEN - COLLISION_PATH_AT];
        let nul = field.iter().position(|&b| b == 0).unwrap_or_default();
        assert!(field[nul + 1..].iter().any(|&b| b != 0));
    }

    #[test]
    fn an_index2_terminator_in_either_key_width_leaves_a_clean_container() {
        // A retail install spells the sentinel both ways, and reading it only one way turns 8 archives
        // into a record keyed all-ones whose zero location word points at a dat's own header.
        for terminator in [Terminator::Wide, Terminator::Narrow] {
            let mut b = clean_index2();
            b.terminator(terminator);
            let inspection = inspect(&b.bytes(), IndexKind::Index2, &[0, 1]);
            assert!(
                inspection.report.findings.is_empty(),
                "{terminator:?}: {:#?}",
                inspection.report.findings
            );
            assert_eq!(inspection.report.totals.collision_records, 2);
        }
    }

    #[test]
    fn an_archive_holding_no_entries_is_clean_in_either_form() {
        // Several archives of a real install are this shape: no entries, no folder table, an empty
        // descriptor declaring the write cursor or zero, and a collision segment that is only its
        // terminator. It is the shape a sweep is most likely to false-positive on.
        for kind in [IndexKind::Index1, IndexKind::Index2] {
            for zeroed in [false, true] {
                let mut b = IndexBuilder::new(kind);
                b.data_file_count(2).terminator(Terminator::Narrow);
                if zeroed {
                    b.zero_empty_segment_offsets();
                }
                let found = findings(&b.bytes(), kind);
                assert!(found.is_empty(), "{kind:?} zeroed={zeroed}: {found:#?}");
            }
        }
    }

    #[test]
    fn an_empty_third_segment_and_a_full_one_are_both_clean() {
        for len in [0usize, 16, 6400] {
            let mut b = clean_index1();
            b.unclassified(len);
            let found = findings(&b.bytes(), IndexKind::Index1);
            assert!(found.is_empty(), "third segment {len}: {found:#?}");
        }
    }

    #[test]
    fn a_hash_field_of_all_zeros_claims_nothing_and_is_counted_instead() {
        // Two dats of a real install declare an all-zero data-region hash where a third declares the
        // digest of nothing. All zeros means unclaimed, so it is skipped rather than compared.
        let mut b = clean_index1();
        b.zero_self_hashes().zero_segment_hashes();
        let inspection = inspect(&b.bytes(), IndexKind::Index1, &[0, 1]);
        assert!(
            inspection.report.findings.is_empty(),
            "{:#?}",
            inspection.report.findings
        );
        // Two header digests and the four non-empty segments.
        assert_eq!(inspection.report.totals.unclaimed_hash_fields, 6);
    }

    // --- the container could not be read ---

    #[test]
    fn a_container_cut_short_is_one_unreadable_finding() {
        let bytes = clean_index1().bytes();
        let inspection = inspect(&bytes[..bytes.len() - 8], IndexKind::Index1, &[0, 1]);
        assert_eq!(inspection.report.findings.len(), 1);
        assert!(matches!(
            inspection.report.findings[0].defect,
            Defect::ContainerUnreadable {
                fault: ReadFault::Truncated,
                ..
            }
        ));
        assert_eq!(inspection.report.totals.containers_unreadable, 1);
        assert!(inspection.index.is_none());
        assert!(inspection.locations.is_empty());
    }

    // --- the hashes a container declares over its own bytes ---

    #[test]
    fn each_header_is_checked_against_the_digest_it_declares_over_itself() {
        for (header, field) in [
            (HeaderId::Common, SELF_HASH_AT as u64),
            (HeaderId::Second, INDEX_HEADER_OFFSET + SELF_HASH_AT as u64),
        ] {
            let mut b = clean_index1();
            b.self_hash(header, [0xAB; 20]);
            let finding = only(&b.bytes(), IndexKind::Index1);
            assert_eq!(finding.site.offset, Some(field));
            match finding.defect {
                Defect::HeaderHashMismatch {
                    header: reported,
                    declared,
                    computed,
                } => {
                    assert_eq!(reported, header);
                    assert_eq!(declared, [0xAB; 20]);
                    assert_ne!(computed, declared);
                }
                other => panic!("expected a header hash mismatch, got {other:?}"),
            }
            assert_eq!(finding.severity(), Severity::Altered);
        }
    }

    #[test]
    fn each_segment_is_checked_against_the_digest_its_descriptor_declares() {
        let bytes = clean_index1().bytes();
        let Ok(index) = Index::parse(&bytes) else {
            panic!("the clean fixture must parse")
        };
        for segment in 0..SEGMENT_COUNT {
            let declared = index.header().segments[segment];
            let mut b = clean_index1();
            b.segment_sha1(segment, [0xCD; 20]);
            let finding = only(&b.bytes(), IndexKind::Index1);
            assert_eq!(finding.site.offset, Some(u64::from(declared.offset)));
            match finding.defect {
                Defect::SegmentHashMismatch {
                    segment: reported,
                    len,
                    declared: claimed,
                    computed,
                } => {
                    assert_eq!(reported, segment as u8);
                    assert_eq!(len, declared.size);
                    assert_eq!(claimed, [0xCD; 20]);
                    assert_ne!(computed, claimed);
                }
                other => panic!("expected a segment hash mismatch, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_two_runs_no_hash_covers_must_be_zero() {
        // These 88 bytes are the only ones in a container that neither self hash nor a segment hash
        // reaches, which is why they are the one place a direct zero check earns its keep.
        for at in [
            SELF_HASH_AT + SELF_HASH_LEN,
            INDEX_HEADER_OFFSET as usize + SELF_HASH_AT + SELF_HASH_LEN,
        ] {
            let mut b = clean_index1();
            b.header_pad(at + 4, &[1]);
            let finding = only(&b.bytes(), IndexKind::Index1);
            assert_eq!(finding.site.offset, Some(at as u64));
            assert_eq!(
                finding.defect,
                Defect::ZeroRegionDirty {
                    len: 44,
                    first_nonzero: at as u64 + 4,
                }
            );
        }
    }

    // --- the words every container spells the same ---

    /// One header word, how to spell it differently, and what the check should then say about it.
    struct WordCase {
        name: &'static str,
        mutate: fn(&mut IndexBuilder),
        word: HeaderWord,
        at: u64,
        declared: u32,
        expected: u32,
    }

    #[test]
    fn each_header_word_that_never_varies_is_checked() {
        let cases = [
            WordCase {
                name: "common size",
                mutate: |b| {
                    b.header_pad(COMMON_HEADER_SIZE_AT as usize, &bytes::write_u32_le(0x800));
                },
                word: HeaderWord::CommonHeaderSize,
                at: COMMON_HEADER_SIZE_AT,
                declared: 0x800,
                expected: 0x400,
            },
            WordCase {
                name: "common version",
                mutate: |b| {
                    b.header_pad(COMMON_VERSION_AT as usize, &bytes::write_u32_le(7));
                },
                word: HeaderWord::CommonVersion,
                at: COMMON_VERSION_AT,
                declared: 7,
                expected: 1,
            },
            WordCase {
                name: "index size",
                mutate: |b| {
                    b.header_size(0x800);
                },
                word: HeaderWord::SecondHeaderSize,
                at: INDEX_HEADER_OFFSET,
                declared: 0x800,
                expected: 0x400,
            },
            WordCase {
                name: "index version",
                mutate: |b| {
                    b.version(7);
                },
                word: HeaderWord::SecondVersion,
                at: INDEX_HEADER_OFFSET + 4,
                declared: 7,
                expected: 1,
            },
        ];
        for case in cases {
            let mut b = clean_index1();
            (case.mutate)(&mut b);
            let finding = only(&b.bytes(), IndexKind::Index1);
            assert_eq!(finding.site.offset, Some(case.at), "{}", case.name);
            assert_eq!(
                finding.defect,
                Defect::HeaderWord {
                    word: case.word,
                    declared: case.declared,
                    expected: case.expected,
                },
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn a_declared_form_the_file_name_contradicts_is_a_finding() {
        // A kind word outside the two the format defines is refused by the reader and lands as an
        // unreadable container instead; this is the case where both words are legal and disagree.
        let finding = only(&clean_index2().bytes(), IndexKind::Index1);
        assert_eq!(finding.site.offset, Some(INDEX_KIND_AT));
        assert_eq!(
            finding.defect,
            Defect::IndexKindDisagreesWithName {
                declared: IndexKind::Index2,
                named: IndexKind::Index1,
            }
        );
    }

    // --- the segment table ---

    #[test]
    fn a_segment_that_does_not_start_where_the_previous_ends_is_a_finding() {
        let mut b = clean_index1();
        b.segment_gap(3, 16);
        let finding = only(&b.bytes(), IndexKind::Index1);
        assert_eq!(finding.site.offset, Some(SEGMENT_DESCRIPTOR_AT[3]));
        match finding.defect {
            Defect::SegmentsDoNotTile {
                segment,
                declared,
                expected,
            } => {
                assert_eq!(segment, 3);
                assert_eq!(declared, expected + 16);
            }
            other => panic!("expected a tiling fault, got {other:?}"),
        }
    }

    #[test]
    fn bytes_past_the_last_segment_are_a_finding() {
        let mut b = clean_index1();
        b.trailing(24);
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(finding.defect, Defect::TrailingBytes { len: 24 });
        assert_eq!(finding.site.offset, Some(bytes.len() as u64 - 24));
    }

    #[test]
    fn a_segment_that_is_not_a_whole_number_of_its_records_is_a_finding() {
        // Only the third segment can reach this check: the reader refuses a ragged entry, collision or
        // folder segment outright, and that refusal is already an unreadable container.
        let mut b = clean_index1();
        b.unclassified(20);
        let finding = only(&b.bytes(), IndexKind::Index1);
        assert_eq!(finding.site.offset, Some(SEGMENT_DESCRIPTOR_AT[2]));
        assert_eq!(
            finding.defect,
            Defect::SegmentRagged {
                segment: 2,
                len: 20,
                record_len: 16,
            }
        );
    }

    #[test]
    fn neither_form_may_carry_the_others_segments() {
        let mut b = clean_index2();
        b.unclassified(16);
        let finding = only(&b.bytes(), IndexKind::Index2);
        assert_eq!(finding.site.offset, Some(SEGMENT_DESCRIPTOR_AT[2]));
        assert_eq!(
            finding.defect,
            Defect::UnclassifiedSegmentOnSecondForm { len: 16 }
        );

        let mut b = clean_index2();
        b.folders(vec![FolderRow {
            hash: 1,
            entries_offset: FIRST_SEGMENT_OFFSET,
            entries_size: 16,
        }]);
        let finding = only(&b.bytes(), IndexKind::Index2);
        assert_eq!(finding.site.offset, Some(SEGMENT_DESCRIPTOR_AT[3]));
        assert_eq!(finding.defect, Defect::FolderTableOnSecondForm { rows: 1 });

        let mut b = clean_index1();
        b.folders(Vec::new());
        let finding = only(&b.bytes(), IndexKind::Index1);
        assert_eq!(finding.site.offset, Some(SEGMENT_DESCRIPTOR_AT[3]));
        assert_eq!(finding.defect, Defect::FolderTableMissing { entries: 4 });
    }

    // --- the entry table ---

    #[test]
    fn entry_keys_must_ascend_and_must_not_repeat() {
        // Two files of one folder, written in descending file-name-hash order: the derived folder table
        // is still one coherent row, so the only thing wrong is the order of the keys.
        let mut paths = ["exd/root.exl", "exd/item.exh"];
        paths.sort_by_key(|path| std::cmp::Reverse(hash_path(path).file));
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .path(paths[0], packed(0, 0x800))
            .path(paths[1], packed(0, 0x1000));
        let finding = only(&b.bytes(), IndexKind::Index1);
        assert_eq!(
            finding.defect,
            Defect::EntryKeysNotAscending {
                previous: hash_path(paths[0]).key()
            }
        );
        assert_eq!(
            finding.site.offset,
            Some(u64::from(FIRST_SEGMENT_OFFSET) + INDEX1_ENTRY_LEN as u64)
        );
        assert_eq!(finding.site.key, Some(hash_path(paths[1]).key()));

        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .path("exd/root.exl", packed(0, 0x800))
            .path("exd/root.exl", packed(0, 0x1000));
        let finding = only(&b.bytes(), IndexKind::Index1);
        assert_eq!(finding.defect, Defect::DuplicateEntryKey);
    }

    #[test]
    fn an_entrys_reserved_word_must_be_zero() {
        let mut b = clean_index1();
        b.entry_pad(1, 0xDEAD_BEEF);
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(finding.defect, Defect::EntryPadNotZero { pad: 0xDEAD_BEEF });
        assert_eq!(
            finding.site.offset,
            Some(u64::from(FIRST_SEGMENT_OFFSET) + INDEX1_ENTRY_LEN as u64)
        );
        // The reader drops this word, so a rewritten container that keeps every location right still
        // differs from what the archive was built as: altered, not damaged.
        assert_eq!(finding.severity(), Severity::Altered);
    }

    #[test]
    fn a_collision_placeholder_carries_only_the_collision_flag() {
        // The placeholder's location word carries an offset it must not have.
        let key = shared_index1_key();
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .path("exd/root.exl", packed(0, 0x800))
            .entry(key, 3)
            .collision(key, packed(1, 0x1000), 0, SHARED_FILE_HASH[0])
            .collision(key, packed(1, 0x1800), 1, SHARED_FILE_HASH[1])
            .sort_entries();
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(finding.defect, Defect::CollisionFlagNotBare { packed: 3 });
        assert_eq!(finding.site.offset, Some(entry_offset(&bytes, key)));
    }

    #[test]
    fn an_entry_may_not_name_a_data_file_the_archive_does_not_declare() {
        let mut b = clean_index1();
        b.data_file_count(1);
        let bytes = b.bytes();
        let inspection = inspect(&bytes, IndexKind::Index1, &[0]);
        let key = hash_path("common/font/font2.tex").key();
        assert_eq!(
            inspection.report.findings,
            [Finding {
                site: Site {
                    container: container(IndexKind::Index1),
                    offset: Some(entry_offset(&bytes, key)),
                    key: Some(key),
                },
                defect: Defect::EntryDatOutOfRange {
                    dat: 1,
                    declared: 1,
                },
            }]
        );
    }

    #[test]
    fn the_declared_data_file_count_is_checked_against_the_directory() {
        let inspection = inspect(&clean_index1().bytes(), IndexKind::Index1, &[0]);
        assert_eq!(inspection.report.findings.len(), 1);
        let finding = inspection.report.findings[0];
        assert_eq!(finding.site.offset, Some(DATA_FILE_COUNT_AT));
        assert_eq!(
            finding.defect,
            Defect::DeclaredDatCount {
                declared: 2,
                present: 1,
            }
        );
        // Which of the two is wrong is not decided here, so the whole archive is the repair unit.
        assert_eq!(finding.scope(), Scope::Archive);
    }

    // --- the collision table ---

    #[test]
    fn a_collision_table_must_end_at_a_terminating_record() {
        let mut b = clean_index1();
        b.terminator(Terminator::Absent);
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(
            finding.defect,
            Defect::CollisionTableUnterminated { records: 2 }
        );
        assert_eq!(finding.site.offset, Some(collision_offset(&bytes, 0)));
    }

    #[test]
    fn a_collision_segment_holding_nothing_at_all_is_unterminated() {
        // A container that lost its table has no offset worth reading, so the descriptor's own position
        // is where the absence is reported from.
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .path("exd/root.exl", packed(0, 0x800))
            .terminator(Terminator::Absent);
        let finding = only(&b.bytes(), IndexKind::Index1);
        assert_eq!(finding.site.offset, Some(SEGMENT_DESCRIPTOR_AT[1]));
        assert_eq!(
            finding.defect,
            Defect::CollisionTableUnterminated { records: 0 }
        );
    }

    #[test]
    fn a_record_past_the_terminator_is_not_the_table() {
        let key = shared_index1_key();
        let mut b = clean_index1();
        b.collision(u64::MAX, 0, u32::MAX, "").collision(
            key,
            packed(1, 0x2000),
            2,
            SHARED_FILE_HASH[0],
        );
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(finding.defect, Defect::CollisionRecordAfterTerminator);
        assert_eq!(finding.site.offset, Some(collision_offset(&bytes, 3)));
    }

    #[test]
    fn a_records_path_must_be_terminated_inside_its_own_field() {
        let key = shared_index1_key();
        let long = "a".repeat(COLLISION_RECORD_LEN);
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .entry(key, 1)
            .collision(key, packed(1, 0x1000), 0, &long)
            .collision(key, packed(1, 0x1800), 1, SHARED_FILE_HASH[1])
            .sort_entries();
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(finding.defect, Defect::CollisionPathUnterminated);
        assert_eq!(finding.site.offset, Some(collision_offset(&bytes, 0)));
        assert_eq!(finding.site.key, Some(key));
    }

    #[test]
    fn a_records_path_must_be_printable_ascii() {
        let key = shared_index1_key();
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .entry(key, 1)
            .collision(key, packed(1, 0x1000), 0, "chara/\u{1}one.mdl")
            .collision(key, packed(1, 0x1800), 1, SHARED_FILE_HASH[1])
            .sort_entries();
        let finding = only(&b.bytes(), IndexKind::Index1);
        assert_eq!(finding.defect, Defect::CollisionPathNotAscii { at: 6 });
    }

    #[test]
    fn a_records_path_must_hash_to_the_key_it_is_filed_under() {
        // The one check in the crate that ties a literal path to a hash rather than a hash to a hash.
        let key = shared_index1_key();
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .entry(key, 1)
            .collision(key, packed(1, 0x1000), 0, "chara/elsewhere.mdl")
            .collision(key, packed(1, 0x1800), 1, SHARED_FILE_HASH[1])
            .sort_entries();
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(
            finding.defect,
            Defect::CollisionPathKeyMismatch {
                hashes_to: hash_path("chara/elsewhere.mdl").key()
            }
        );
        assert_eq!(finding.site.offset, Some(collision_offset(&bytes, 0)));
    }

    #[test]
    fn a_record_may_not_itself_be_a_placeholder() {
        let key = shared_index1_key();
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .entry(key, 1)
            .collision(key, packed(1, 0x1000) | 1, 0, SHARED_FILE_HASH[0])
            .collision(key, packed(1, 0x1800), 1, SHARED_FILE_HASH[1])
            .sort_entries();
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(
            finding.defect,
            Defect::CollisionRecordIsPlaceholder {
                packed: packed(1, 0x1000) | 1
            }
        );
        assert_eq!(finding.site.offset, Some(collision_offset(&bytes, 0)));
    }

    #[test]
    fn the_conflict_indexes_under_one_key_are_each_of_them_once() {
        let key = shared_index1_key();
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .entry(key, 1)
            .collision(key, packed(1, 0x1000), 0, SHARED_FILE_HASH[0])
            .collision(key, packed(1, 0x1800), 2, SHARED_FILE_HASH[1])
            .sort_entries();
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(
            finding.defect,
            Defect::CollisionConflictIndexUnexpected {
                conflict_index: 2,
                records: 2,
            }
        );
        assert_eq!(finding.site.offset, Some(collision_offset(&bytes, 1)));
    }

    #[test]
    fn the_flagged_entries_and_the_records_name_the_same_keys() {
        let key = shared_index1_key();
        // A key with records but no entry flagging it.
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .entry(key, packed(0, 0x800))
            .collision(key, packed(1, 0x1000), 0, SHARED_FILE_HASH[0])
            .collision(key, packed(1, 0x1800), 1, SHARED_FILE_HASH[1])
            .sort_entries();
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(finding.defect, Defect::CollisionRecordWithoutFlaggedEntry);
        assert_eq!(finding.site.offset, Some(collision_offset(&bytes, 0)));

        // A flagged entry whose key carries fewer records than a collision needs. The check is "at
        // least two": a three-way collision is possible in principle, so an exact count would be a
        // property of the collisions that happened rather than of the format.
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(2)
            .entry(key, 1)
            .collision(key, packed(1, 0x1000), 0, SHARED_FILE_HASH[0])
            .sort_entries();
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(
            finding.defect,
            Defect::FlaggedEntryWithoutRecords { records: 1 }
        );
        assert_eq!(finding.site.offset, Some(entry_offset(&bytes, key)));
    }

    // --- the folder table ---

    #[test]
    fn a_folder_rows_reserved_word_must_be_zero() {
        let mut b = clean_index1();
        b.folder_pad(1, 9);
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(finding.site.offset, Some(folder_offset(&bytes, 1)));
        assert!(matches!(
            finding.defect,
            Defect::FolderRowPadNotZero { pad: 9, .. }
        ));
    }

    #[test]
    fn the_folder_rows_must_tile_the_entry_segment_exactly() {
        let mut rows = clean_folder_rows();
        let Some(last) = rows.last_mut() else {
            panic!("the clean fixture must derive a folder table")
        };
        last.entries_size -= INDEX1_ENTRY_LEN as u32;
        let short_by = rows.len() - 1;
        let mut b = clean_index1();
        b.folders(rows);
        let bytes = b.bytes();
        let finding = only(&bytes, IndexKind::Index1);
        assert_eq!(finding.site.offset, Some(folder_offset(&bytes, short_by)));
        match finding.defect {
            Defect::FolderRowsDoNotTile { declared, expected } => {
                assert_eq!(declared + INDEX1_ENTRY_LEN as u32, expected);
            }
            other => panic!("expected a folder tiling fault, got {other:?}"),
        }
    }

    #[test]
    fn a_row_naming_a_run_that_is_not_its_own_is_reported_rather_than_walked() {
        // Nothing in the format stops every row of a folder table naming the whole entry table, and the
        // reader hands back whatever run a row names. Judging the entries of a run the rows do not tile
        // would cost the product of the two segments, which is minutes over a container the size of a
        // real `chara` index and hours over one at the reader's cap. The counts are the proof, because
        // the work and the findings are one walk.
        let rows = 512u32;
        let mut b = IndexBuilder::new(IndexKind::Index1);
        b.data_file_count(1);
        for i in 0..u64::from(rows) {
            b.entry(i + 1, packed(0, (i + 1) * 128));
        }
        let whole = rows * INDEX1_ENTRY_LEN as u32;
        b.folders(
            (0..rows)
                .map(|i| FolderRow {
                    hash: i + 1,
                    entries_offset: FIRST_SEGMENT_OFFSET,
                    entries_size: whole,
                })
                .collect(),
        );
        let report = inspect(&b.bytes(), IndexKind::Index1, &[0]).report;
        // One per row whose run is not where the previous one ended, plus one per entry of the one row
        // whose is: linear in the container, where walking every row's run is its square.
        let filed = report.findings.len() as u64 + report.totals.defects_suppressed;
        assert_eq!(filed, u64::from(rows) * 2 - 1, "{filed} finding(s) filed");
    }

    #[test]
    fn every_entry_in_a_folders_run_carries_that_folders_hash() {
        let mut rows = clean_folder_rows();
        // Keep the rows ascending, so the only thing wrong is which folder the run is labelled with.
        let labelled = rows.first().map_or(0, |first| first.hash) + 1;
        let Some(row) = rows.get_mut(1) else {
            panic!("the clean fixture must derive several folder rows")
        };
        let real = row.hash;
        row.hash = labelled;
        let mut b = clean_index1();
        b.folders(rows);
        let found = findings(&b.bytes(), IndexKind::Index1);
        assert!(
            found.iter().all(|f| f.defect
                == Defect::FolderHashDisagreesWithEntry {
                    folder: labelled,
                    entry_folder: real,
                }),
            "{found:#?}"
        );
        assert!(!found.is_empty());
    }

    #[test]
    fn folder_rows_must_ascend_by_hash() {
        // A row's hash cannot be lowered without also parting company with the entries in its run, so
        // this is the one mutation that fires two checks, and both of them are the point.
        let mut rows = clean_folder_rows();
        let previous = rows.first().map_or(0, |first| first.hash);
        let lowered = previous - 1;
        let Some(row) = rows.get_mut(1) else {
            panic!("the clean fixture must derive several folder rows")
        };
        row.hash = lowered;
        let mut b = clean_index1();
        b.folders(rows);
        let found = findings(&b.bytes(), IndexKind::Index1);
        assert!(
            found.iter().any(|f| f.defect
                == Defect::FolderRowsNotAscending {
                    hash: lowered,
                    previous,
                }),
            "{found:#?}"
        );
        assert!(
            found.iter().all(|f| matches!(
                f.defect,
                Defect::FolderRowsNotAscending { .. } | Defect::FolderHashDisagreesWithEntry { .. }
            )),
            "{found:#?}"
        );
    }

    // --- the two forms against each other ---

    #[test]
    fn the_two_forms_of_one_archive_must_name_the_same_locations() {
        let paths = [
            ("exd/root.exl", packed(0, 0x800)),
            ("common/font/font1.tex", packed(1, 0x1000)),
        ];
        let mut one = IndexBuilder::new(IndexKind::Index1);
        let mut two = IndexBuilder::new(IndexKind::Index2);
        for (path, location) in paths {
            one.path(path, location);
            two.path(path, location);
        }
        one.data_file_count(2).sort_entries();
        two.data_file_count(2).sort_entries();
        let archive = container(IndexKind::Index1).with_file(ContainerId::Archive);
        let first = inspect(&one.bytes(), IndexKind::Index1, &[0, 1]).locations;
        let second = inspect(&two.bytes(), IndexKind::Index2, &[0, 1]).locations;
        let agree = compare_index_forms(&first, &second, archive, &SweepOptions::default());
        assert!(agree.findings.is_empty());
        assert_eq!(agree.totals, Totals::default());
        assert!(!agree.truncated);

        // Move one location in the second form only: the same byte range is then named by one form and
        // not the other, in both directions.
        let mut moved = IndexBuilder::new(IndexKind::Index2);
        moved
            .data_file_count(2)
            .path("exd/root.exl", packed(0, 0x800))
            .path("common/font/font1.tex", packed(1, 0x2000))
            .sort_entries();
        let moved = inspect(&moved.bytes(), IndexKind::Index2, &[0, 1]).locations;
        let report = compare_index_forms(&first, &moved, archive, &SweepOptions::default());
        let found = report.findings;
        assert_eq!(
            found
                .iter()
                .map(|finding| finding.defect)
                .collect::<Vec<_>>(),
            [
                Defect::FormsDisagree {
                    only_in: IndexKind::Index1,
                    dat: 1,
                    offset: 0x1000,
                },
                Defect::FormsDisagree {
                    only_in: IndexKind::Index2,
                    dat: 1,
                    offset: 0x2000,
                },
            ]
        );
        assert_eq!(
            found[0].site.container.file,
            ContainerId::Index(IndexKind::Index1)
        );
        assert_eq!(
            found[1].site.container.file,
            ContainerId::Index(IndexKind::Index2)
        );
        assert_eq!(report.totals.defects_suppressed, 0);
        assert!(!report.truncated);

        // The same disagreement under a budget of one: what the comparison declined to carry is what
        // it counted, so a caller reading the count is not told a report that ends is a whole one, and
        // a comparison that fits exactly is not reported as one that stopped.
        let tight = |cap| {
            compare_index_forms(
                &first,
                &moved,
                archive,
                &SweepOptions {
                    max_defects_per_container: cap,
                    ..SweepOptions::default()
                },
            )
        };
        let report = tight(1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.totals.defects_suppressed, 1);
        assert!(report.truncated);
        let report = tight(2);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.totals.defects_suppressed, 0);
        assert!(!report.truncated);
    }

    #[test]
    fn a_second_form_that_folds_a_collision_still_names_the_same_locations() {
        // The `.index2` holds one entry fewer than the `.index` here, because the two paths share a
        // whole-path hash and fold into a placeholder plus a record apiece. Comparing entry counts
        // would call that a fault; comparing locations does not.
        let key = shared_index2_key();
        let mut one = IndexBuilder::new(IndexKind::Index1);
        one.path(SHARED_PATH_HASH[0], packed(0, 0x800))
            .path(SHARED_PATH_HASH[1], packed(0, 0x1000))
            .sort_entries();
        let mut two = IndexBuilder::new(IndexKind::Index2);
        two.entry(key, 1)
            .collision(key, packed(0, 0x800), 0, SHARED_PATH_HASH[0])
            .collision(key, packed(0, 0x1000), 1, SHARED_PATH_HASH[1]);
        let first = inspect(&one.bytes(), IndexKind::Index1, &[0]).locations;
        let second = inspect(&two.bytes(), IndexKind::Index2, &[0]).locations;
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        let archive = container(IndexKind::Index1).with_file(ContainerId::Archive);
        assert!(
            compare_index_forms(&first, &second, archive, &SweepOptions::default())
                .findings
                .is_empty()
        );
    }

    // --- the budget ---

    #[test]
    fn the_budget_keeps_what_it_can_and_counts_the_rest() {
        let mut b = IndexBuilder::new(IndexKind::Index1);
        for i in 0..64u64 {
            b.entry(i + 1, packed(0, (i + 1) * 128));
            b.entry_pad(i as usize, 1);
        }
        let facts = IndexFacts {
            container: container(IndexKind::Index1),
            named: IndexKind::Index1,
            dats: &[0],
        };
        let opts = SweepOptions {
            max_defects_per_container: 4,
            ..SweepOptions::default()
        };
        let report = inspect_index(&b.bytes(), &facts, &opts).report;
        assert_eq!(report.findings.len(), 4);
        assert!(report.truncated);
        assert_eq!(report.totals.defects_suppressed, 60);
    }

    // --- the header layout the checks address by offset ---

    #[test]
    fn the_header_field_offsets_are_where_the_reader_reads_them() {
        // The reader takes the index header's fields in sequence; the checks name them by position.
        // These are the same bytes, and a divergence would file findings against the wrong words.
        let mut b = clean_index1();
        b.data_file_count(6);
        let bytes = b.bytes();
        let Ok(index) = Index::parse(&bytes) else {
            panic!("the clean fixture must parse")
        };
        for (n, descriptor) in index.header().segments.iter().enumerate() {
            let at = SEGMENT_DESCRIPTOR_AT[n] as usize;
            assert_eq!(u32_at(&bytes, at), Some(descriptor.offset), "segment {n}");
            assert_eq!(u32_at(&bytes, at + 4), Some(descriptor.size), "segment {n}");
            assert_eq!(
                digest_at(&bytes, at + 8),
                Some(descriptor.sha1),
                "segment {n}"
            );
        }
        assert_eq!(u32_at(&bytes, DATA_FILE_COUNT_AT as usize), Some(6));
        assert_eq!(
            u32_at(&bytes, INDEX_KIND_AT as usize),
            Some(IndexKind::Index1.word())
        );
    }

    // Two properties a fixture cannot state. The first is the anti-false-positive one: whatever legal
    // shape a container takes, the checks find nothing. The second is the coverage one: the six digests
    // and the two zero runs between them account for every byte of a container, so no byte can be
    // changed without something noticing.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn any_coherent_container_is_clean(
            keys in prop::collection::btree_set(any::<u64>(), 0..24),
            third in 0usize..8,
            index2 in any::<bool>(),
            narrow in any::<bool>(),
        ) {
            let kind = if index2 { IndexKind::Index2 } else { IndexKind::Index1 };
            // An `.index2` stores only the low half of a key, so two keys distinct as `u64` are one
            // entry once written: narrow them first and the table stays unique in the width it has.
            let mut keys: Vec<u64> = keys
                .iter()
                .map(|key| if index2 { u64::from(*key as u32) } else { *key })
                .collect();
            keys.sort_unstable();
            keys.dedup();
            let mut b = IndexBuilder::new(kind);
            b.data_file_count(2).sort_entries();
            if !index2 {
                b.unclassified(third * 16);
            }
            if narrow {
                b.terminator(Terminator::Narrow);
            }
            for (i, key) in keys.iter().enumerate() {
                b.entry(*key, packed((i % 2) as u8, (i as u64 + 16) * 128));
            }
            let found = findings(&b.bytes(), kind);
            prop_assert!(found.is_empty(), "{:#?}", found);
        }

        #[test]
        fn no_byte_of_a_container_can_change_unnoticed(
            at in 0usize..0x1000,
            bit in 0u32..8,
        ) {
            let mut bytes = clean_index1().bytes();
            let at = at % bytes.len();
            bytes[at] ^= 1 << bit;
            let found = findings(&bytes, IndexKind::Index1);
            prop_assert!(!found.is_empty(), "byte {:#x} bit {} went unnoticed", at, bit);
        }
    }
}
