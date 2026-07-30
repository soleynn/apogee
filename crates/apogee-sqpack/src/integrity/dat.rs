//! The dat container's checks: what a `.dat{n}` declares about itself against what it holds, and what
//! the locations an index named turn out to be sitting on.
//!
//! Three passes over one container, because they cost three different things. The headers are the
//! first `0x800` bytes and answer for themselves. The slot walk reads twenty bytes at every location
//! an index named, which is what proves an index and its data files agree, and it is what makes the
//! space between slots measurable at all: a run no slot covers can only be recognised once the slots
//! are known. Hashing the declared data region and extracting every entry read the whole container,
//! so both are asked for rather than assumed.
//!
//! A dat with no `SqPack` magic is normal (nineteen of a full install's eighty-six), so its absence is
//! recorded and never reported, and its common header's words are checked only when it has one.

use std::io::Write;

use sha1::{Digest, Sha1};

use super::finding::{Sink, read_fault};
use crate::container::COMMON_HEADER_LEN;
use crate::dat::{
    ContentType, DATA_HEADER_LEN, DATA_HEADER_SIZE_AT, DATA_REGION_OFFSET, DATA_RESERVED_AT,
    DATA_UNCLASSIFIED_AT, DATA_UNIT, DATA_UNITS_AT, Dat, DatSource, EMPTY_BLOCK_HEADER_LEN,
    EntryHeader, FileSource, empty_block_count,
};
use crate::integrity::{
    COMMON_HEADER_SIZE_AT, COMMON_VERSION_AT, ContainerRef, ContainerReport, Defect,
    FORMAT_VERSION, GapPolicy, HASH_CHUNK_BYTES, HeaderWord, Located, SweepOptions, Totals,
    UNCLAIMED_DIGEST, check_self_hashes, check_uncovered_runs, u32_at,
};

/// How much of a container the two headers take, and so how much one read covers both.
const HEADERS_LEN: usize = COMMON_HEADER_LEN + DATA_HEADER_LEN as usize;

/// What the data header's word at `0x08` spells in every dat file of a full install.
const DATA_UNCLASSIFIED: u32 = 16;

/// Which reserved word each of [`DATA_RESERVED_AT`]'s positions is, so a finding names the one it
/// found rather than an index into an array a reader cannot see.
const RESERVED_WORDS: [HeaderWord; 3] = [
    HeaderWord::DataReserved0,
    HeaderWord::DataReserved1,
    HeaderWord::DataReserved2,
];

/// The content types the format defines, which is every type a full install's 1.9 M entries declare.
const KNOWN_CONTENT_TYPES: [ContentType; 4] = [
    ContentType::Empty,
    ContentType::Standard,
    ContentType::Model,
    ContentType::Texture,
];

/// What inspecting a dat container's headers produced.
#[derive(Debug)]
pub struct DatInspection<S = FileSource> {
    /// The findings and what the checks accounted for.
    pub report: ContainerReport,
    /// The parsed container, handed back so the two expensive passes reuse the parse rather than
    /// opening it again. `None` exactly when the report carries a [`Defect::ContainerUnreadable`].
    pub dat: Option<Dat<S>>,
}

/// Check a dat container's two headers and the length they imply.
///
/// Reads the first `0x800` bytes once: the two self hashes, the header words every container spells
/// the same, the two runs no hash covers and the declared length all come out of them.
#[must_use]
pub fn inspect_dat_headers<S: DatSource>(
    source: S,
    at: ContainerRef,
    opts: &SweepOptions,
) -> DatInspection<S> {
    let mut sink = Sink::new(at, opts.max_defects_per_container);
    let mut totals = Totals {
        data_files: 1,
        ..Totals::default()
    };

    let mut head = vec![0u8; HEADERS_LEN];
    match source.read_at(&mut head, 0) {
        // A container shorter than its own headers still has whatever it has: the parse below is what
        // decides that is not enough, and the checks that reach past the end skip themselves.
        Ok(read) => head.truncate(read),
        Err(error) => {
            let (fault, detail, offset) = read_fault(&error);
            sink.push_on(offset, Defect::ContainerUnreadable { fault, detail });
            totals.containers_unreadable = 1;
            return DatInspection {
                report: sink.finish(totals),
                dat: None,
            };
        }
    }

    let dat = match Dat::from_source(source, &opts.dat_limits) {
        Ok(dat) => dat,
        Err(error) => {
            let (fault, detail, offset) = read_fault(&error);
            sink.push_on(offset, Defect::ContainerUnreadable { fault, detail });
            totals.containers_unreadable = 1;
            return DatInspection {
                report: sink.finish(totals),
                dat: None,
            };
        }
    };

    check_header_words(&dat, &head, &mut sink);
    check_self_hashes(&head, &mut sink, &mut totals);
    check_uncovered_runs(&head, &mut sink);
    let declared = dat.data_header().declared_file_len();
    if declared != dat.len() {
        sink.push_at(
            DATA_UNITS_AT,
            Defect::DeclaredLength {
                declared,
                actual: dat.len(),
            },
        );
    }

    DatInspection {
        report: sink.finish(totals),
        dat: Some(dat),
    }
}

/// Verify the SHA-1 the data header claims over the data region, streaming it in fixed windows.
///
/// Nothing is reported when the claim is all zeros, which two dat files of a full install write; the
/// skip is counted in [`Totals::unclaimed_hash_fields`]. Nothing is read when the declared region runs
/// past the end of the file, because [`Defect::DeclaredLength`] has already said so and hashing what
/// is there would only report a second difference derived from the first.
#[must_use]
pub fn inspect_data_region<S: DatSource>(dat: &Dat<S>, at: ContainerRef) -> ContainerReport {
    // One digest, one comparison, so at most one finding.
    let mut sink = Sink::new(at, 1);
    let mut totals = Totals::default();
    let declared = dat.data_header().data_sha1;
    let end = dat.data_header().declared_file_len();
    if declared == UNCLAIMED_DIGEST {
        totals.unclaimed_hash_fields += 1;
        return sink.finish(totals);
    }
    if end > dat.len() {
        return sink.finish(totals);
    }

    let mut hasher = Sha1::new();
    let mut window = vec![0u8; HASH_CHUNK_BYTES];
    let mut pos = DATA_REGION_OFFSET;
    while pos < end {
        let want = usize::try_from(end - pos)
            .unwrap_or(usize::MAX)
            .min(window.len());
        if let Err(error) = dat.source().read_exact_at(&mut window[..want], pos) {
            // The length was checked above, so a short read here means the file changed under the
            // sweep. Nothing is known about the region after that, which is what this says.
            let (fault, detail, offset) = read_fault(&error);
            sink.push_on(offset, Defect::ContainerUnreadable { fault, detail });
            return sink.finish(totals);
        }
        hasher.update(&window[..want]);
        totals.bytes_hashed += want as u64;
        pos += want as u64;
    }

    let computed: [u8; 20] = hasher.finalize().into();
    if computed != declared {
        sink.push_at(
            DATA_REGION_OFFSET,
            Defect::DataRegionHashMismatch {
                len: end - DATA_REGION_OFFSET,
                declared,
                computed,
            },
        );
    }
    sink.finish(totals)
}

/// Walk every location an index named in this container: read each entry's twenty-byte header, account
/// for the space its slot claims, classify whatever the slots do not cover, and (when
/// `opts.decode_entries`) extract every entry and throw it away.
///
/// `named` must be ascending by `(dat, offset, key)` and hold only this container's locations, which is
/// what [`super::IndexInspection::locations`] gives after filtering on `dat`. An empty slice is a dat
/// no index names: its whole data region then reads as one unclaimed run, which is what a lost entry
/// table looks like.
#[must_use]
pub fn inspect_dat_entries<S: DatSource>(
    dat: &Dat<S>,
    named: &[Located],
    at: ContainerRef,
    opts: &SweepOptions,
) -> ContainerReport {
    let mut sink = Sink::new(at, opts.max_defects_per_container);
    let mut totals = Totals::default();
    // The walk is clipped to the file rather than to what the header declares, so a container whose
    // declared region runs past its end (already a finding of its own) still accounts honestly for the
    // bytes that are there.
    let region_end = dat.data_header().declared_file_len().min(dat.len());
    totals.data_region_bytes = region_end.saturating_sub(DATA_REGION_OFFSET);

    let mut covered_to = DATA_REGION_OFFSET;
    // The slot reaching furthest so far, as `(offset, key, slot_len)`. Not the one just visited: a
    // single overgrown slot can span several entries, and the entries it swallowed are the right length
    // themselves. Its own end is also what an overlap is measured against: `covered_to` is where the
    // accounting has reached, which starts at the region and is clipped to it, so it answers for space
    // rather than for any one slot.
    let mut furthest: Option<(u64, u64, u64)> = None;
    for location in named {
        let offset = location.offset;
        let key = location.key;
        let header = match dat.entry_header_at(offset) {
            Ok(header) => header,
            Err(error) => {
                let (fault, detail, _) = read_fault(&error);
                sink.push_keyed(offset, key, Defect::EntryHeaderUnreadable { fault, detail });
                continue;
            }
        };
        totals.entry_headers_read += 1;
        check_entry_header(&header, offset, key, &mut sink);

        let slot_len = header.slot_len();
        let slot_end = offset.saturating_add(slot_len);
        if offset < DATA_REGION_OFFSET {
            sink.push_keyed(offset, key, Defect::SlotBeforeDataRegion);
        }
        if slot_end > region_end {
            sink.push_keyed(
                offset,
                key,
                Defect::SlotBeyondDataRegion {
                    slot_end,
                    region_end,
                },
            );
        }
        // Reported against the slot that reaches too far rather than the one it reaches into, which is
        // the entry a repair would have to re-place.
        if let Some((over_offset, over_key, over_len)) = furthest
            && offset < over_offset.saturating_add(over_len)
        {
            sink.push_keyed(
                over_offset,
                over_key,
                Defect::SlotsOverlap {
                    slot_len: over_len,
                    next_offset: offset,
                },
            );
        }
        if furthest.is_none_or(|(at, _, len)| at.saturating_add(len) < slot_end) {
            furthest = Some((offset, key, slot_len));
        }

        // Claimed space is the union of the slots, so the accounting closes even where they overlap.
        // Both ends are held inside the region, each against its own bound: a location past the end of
        // a region shorter than the file contributes no run, or the space between the last slot and it
        // would be counted as unclaimed region bytes and read as a chain of wiped ones, and a container
        // cut short of `0x800` has a region ending before it begins.
        let start = offset.max(DATA_REGION_OFFSET).min(region_end);
        let end = slot_end.min(region_end);
        if start > covered_to {
            record_gap(dat, covered_to, start, opts, &mut sink, &mut totals);
        }
        if end > start.max(covered_to) {
            totals.claimed_bytes += end - start.max(covered_to);
        }
        covered_to = covered_to.max(end);
        totals.slack_bytes +=
            u64::from(header.allocated_units.saturating_sub(header.occupied_units))
                * u64::from(DATA_UNIT);

        if opts.decode_entries {
            decode(dat, offset, key, &mut sink, &mut totals);
        }
    }
    if covered_to < region_end {
        record_gap(dat, covered_to, region_end, opts, &mut sink, &mut totals);
    }

    sink.finish(totals)
}

/// The words every entry header of a full install spells within a known set: a content type the format
/// defines, a header length that is a whole number of units, and no more stored than reserved.
fn check_entry_header(header: &EntryHeader, offset: u64, key: u64, sink: &mut Sink) {
    if !KNOWN_CONTENT_TYPES.contains(&header.content_type) {
        sink.push_keyed(
            offset,
            key,
            Defect::EntryContentTypeUnknown {
                declared: header.content_type.word(),
            },
        );
    }
    // A length below the five words is refused by the parse, so what is left here is a length that is
    // long enough and still not a whole number of units. The observed ceiling (45,184) is deliberately
    // not a check: a patch may exceed it.
    if !header.header_size.is_multiple_of(DATA_UNIT) {
        sink.push_keyed(
            offset,
            key,
            Defect::EntryHeaderMisaligned {
                header_size: header.header_size,
            },
        );
    }
    if header.occupied_units > header.allocated_units {
        sink.push_keyed(
            offset,
            key,
            Defect::OccupiedExceedsAllocated {
                occupied_units: header.occupied_units,
                allocated_units: header.allocated_units,
            },
        );
    }
}

/// Account for one run of the data region no slot covers, and under [`GapPolicy::Chain`] check that
/// the chain of wiped regions a patcher stamps tiles it exactly.
///
/// The count each region declares describes that region and not the run: adjacent deletions merge and
/// later patches reoccupy part of what they left, so a run is often several regions and the sum is the
/// only thing worth checking. Bytes past a region's own header are whatever the patcher left there and
/// are deliberately not read.
fn record_gap<S: DatSource>(
    dat: &Dat<S>,
    start: u64,
    end: u64,
    opts: &SweepOptions,
    sink: &mut Sink,
    totals: &mut Totals,
) {
    let len = end - start;
    totals.gaps += 1;
    totals.unclaimed_bytes += len;
    totals.largest_gap = totals.largest_gap.max(len);
    if opts.gaps == GapPolicy::Skip {
        return;
    }

    let mut head = [0u8; EMPTY_BLOCK_HEADER_LEN];
    let mut pos = start;
    let mut regions = 0u32;
    while pos < end {
        // Each step is at least one unit, so the walk always advances: `empty_block_count` never
        // answers zero blocks.
        let span = dat
            .source()
            .read_exact_at(&mut head, pos)
            .ok()
            .and_then(|()| empty_block_count(&head))
            .and_then(|blocks| blocks.checked_mul(u64::from(DATA_UNIT)))
            .filter(|span| pos.saturating_add(*span) <= end);
        let Some(span) = span else { break };
        pos += span;
        regions += 1;
    }
    totals.unclaimed_regions += u64::from(regions);
    if pos != end {
        sink.push_at(
            start,
            Defect::GapNotEmptyBlockChain {
                len,
                covered: pos - start,
                regions,
            },
        );
    }
}

/// Extract one entry and throw the bytes away, reporting what the reader refused and how far it got.
///
/// The pass invents no length rule of its own: it reports exactly what [`Dat::read_into`] refuses,
/// which already exempts the volume textures whose declared length counts mip padding the archive does
/// not store.
fn decode<S: DatSource>(dat: &Dat<S>, offset: u64, key: u64, sink: &mut Sink, totals: &mut Totals) {
    let mut discard = Discard(0);
    let outcome = dat
        .entry_at(offset)
        .and_then(|entry| dat.read_into(&entry, &mut discard));
    match outcome {
        Ok(_) => totals.entries_decoded += 1,
        Err(error) => {
            let (fault, detail, _) = read_fault(&error);
            sink.push_keyed(
                offset,
                key,
                Defect::EntryDecodeFailed {
                    fault,
                    detail,
                    produced: discard.0,
                },
            );
        }
    }
}

/// The words a dat container spells the same as every other. The magic is not among them: nineteen of
/// a full install's eighty-six dat files carry none, so a common header is judged only when it is
/// there. The data header carries no version word, which is why only its length is checked.
fn check_header_words<S: DatSource>(dat: &Dat<S>, head: &[u8], sink: &mut Sink) {
    if let Some(common) = dat.common_header() {
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
    }

    let data = dat.data_header();
    if data.header_size != DATA_HEADER_LEN {
        sink.push_at(
            DATA_HEADER_SIZE_AT,
            Defect::HeaderWord {
                word: HeaderWord::SecondHeaderSize,
                declared: data.header_size,
                expected: DATA_HEADER_LEN,
            },
        );
    }
    if data.unclassified != DATA_UNCLASSIFIED {
        sink.push_at(
            DATA_UNCLASSIFIED_AT,
            Defect::HeaderWord {
                word: HeaderWord::DataUnclassified,
                declared: data.unclassified,
                expected: DATA_UNCLASSIFIED,
            },
        );
    }
    // The three words the parse skips, read from the bytes it was handed: nothing carries them.
    for (n, at) in DATA_RESERVED_AT.iter().enumerate() {
        let Some(word) = u32_at(head, usize::try_from(*at).unwrap_or(usize::MAX)) else {
            continue;
        };
        if word != 0 {
            sink.push_at(
                *at,
                Defect::HeaderWord {
                    word: RESERVED_WORDS[n],
                    declared: word,
                    expected: 0,
                },
            );
        }
    }
}

/// A sink for the decode pass: the bytes are counted and dropped, so extracting a whole install never
/// holds a file.
struct Discard(u64);

impl Write for Discard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveId;
    use crate::bytes;
    use crate::dat::builder::{DatBuilder, EntrySpec, Placed};
    use crate::dat::{DATA_HEADER_OFFSET, ENTRY_HEADER_LEN, MODEL_LOD_COUNT, empty_block_header};
    use crate::game::Repo;
    use crate::integrity::{
        ContainerId, Finding, HeaderId, ReadFault, SELF_HASH_AT, SELF_HASH_LEN, Scope, Severity,
        sha1,
    };
    use proptest::prelude::*;

    /// The word an entry header carries its reserved slot size in, which several mutations rewrite.
    const ALLOCATED_UNITS_AT: usize = 0x0C;

    /// And the one it carries what it stores in.
    const OCCUPIED_UNITS_AT: usize = 0x10;

    fn container() -> ContainerRef {
        ContainerRef::new(Repo::Base, ArchiveId::new(0x04, 0, 0), ContainerId::Dat(0))
    }

    fn model_sections() -> [Vec<u8>; 2 + 3 * MODEL_LOD_COUNT] {
        let mut sections: [Vec<u8>; 2 + 3 * MODEL_LOD_COUNT] = Default::default();
        sections[0] = b"stack".repeat(20);
        sections[1] = b"runtime".repeat(30);
        sections[2] = vec![7u8; 4096];
        sections[4] = vec![1u8; 300];
        sections
    }

    /// A byte-faithful dat carrying, on purpose, every shape a pristine install varies on that a naive
    /// check would trip over: one entry of each content type, a volume texture declaring more than it
    /// stores, a standard entry whose size, allocation and occupancy words are all zero, another
    /// occupying nothing under a large allocation, slack inside a slot, a `span_index` that is not the
    /// dat number, a `max_file_size` the file exceeds, a single wiped region and a chain of three.
    fn clean_dat() -> DatBuilder {
        let mut b = DatBuilder::new();
        b.span_index(4)
            .max_file_size(2_000)
            .entry(EntrySpec::standard(vec![
                b"the quick brown fox ".repeat(40),
            ]))
            // An empty entry's size and block-count words still describe its slot's previous occupant;
            // its allocation is the slot it really holds, which is what the slack knob lays down.
            .slack(2)
            .entry(EntrySpec::empty_with_leftovers(83_952, 2, 57_472))
            .slack(0)
            .gap(3)
            .entry(EntrySpec::texture_blocks(
                vec![0xAB; 80],
                vec![vec![vec![1u8; 4096], vec![2u8; 4096]], vec![vec![3u8; 256]]],
            ))
            .entry(EntrySpec::model(model_sections()))
            .entry(EntrySpec::texture_declaring(
                vec![0xCD; 80],
                vec![vec![3u8; 512]],
                4096,
            ))
            .entry(EntrySpec::standard(vec![]))
            .slack(8)
            .entry(EntrySpec::standard(vec![]))
            .slack(4)
            .entry(EntrySpec::standard(vec![b"shrank in place".to_vec()]))
            .slack(0)
            .gap_chain(&[2, 1, 5]);
        b
    }

    /// The locations an index would name for these entries, ascending, each under a key of its own so a
    /// finding says which entry it was about.
    fn located(placed: &[Placed]) -> Vec<Located> {
        placed
            .iter()
            .enumerate()
            .map(|(i, at)| Located {
                dat: 0,
                offset: at.offset,
                key: 0x1000 + i as u64,
            })
            .collect()
    }

    fn headers(bytes: &[u8]) -> DatInspection<&[u8]> {
        inspect_dat_headers(bytes, container(), &SweepOptions::default())
    }

    /// The one finding a mutation to the headers is expected to produce. An over-eager neighbouring
    /// check shows up here as a second finding, which is the point of asserting the count.
    fn only_header_finding(bytes: &[u8]) -> Finding {
        let found = headers(bytes).report.findings;
        assert_eq!(found.len(), 1, "expected one finding, got {found:#?}");
        found[0]
    }

    fn walk(bytes: &[u8], named: &[Located], opts: &SweepOptions) -> ContainerReport {
        let Some(dat) = inspect_dat_headers(bytes, container(), opts).dat else {
            panic!("the container under test must parse")
        };
        inspect_dat_entries(&dat, named, container(), opts)
    }

    /// The one finding a mutation reachable only by walking the entries is expected to produce.
    fn only_walk_finding(bytes: &[u8], named: &[Located], opts: &SweepOptions) -> Finding {
        let found = walk(bytes, named, opts).findings;
        assert_eq!(found.len(), 1, "expected one finding, got {found:#?}");
        found[0]
    }

    /// Every pass a sweep can be asked for, so a clean container can be shown to stay clean as passes
    /// are added.
    fn every_pass() -> [SweepOptions; 4] {
        [
            SweepOptions::default(),
            SweepOptions {
                gaps: GapPolicy::Skip,
                ..SweepOptions::default()
            },
            SweepOptions {
                hash_data_regions: true,
                ..SweepOptions::default()
            },
            SweepOptions {
                decode_entries: true,
                ..SweepOptions::default()
            },
        ]
    }

    // --- the gate: a coherent container produces nothing at all ---

    #[test]
    fn a_clean_container_yields_no_findings_under_any_pass() {
        let built = clean_dat().built();
        let named = located(&built.placed);
        for opts in every_pass() {
            let inspection = inspect_dat_headers(&built.bytes[..], container(), &opts);
            assert!(
                inspection.report.findings.is_empty(),
                "{:#?}",
                inspection.report.findings
            );
            let Some(dat) = inspection.dat else {
                panic!("the clean fixture must parse")
            };
            let region = inspect_data_region(&dat, container());
            assert!(region.findings.is_empty(), "{:#?}", region.findings);
            let walked = inspect_dat_entries(&dat, &named, container(), &opts);
            assert!(walked.findings.is_empty(), "{:#?}", walked.findings);
            assert!(!walked.truncated);
        }

        let totals = walk(&built.bytes, &named, &SweepOptions::default()).totals;
        assert_eq!(totals.entry_headers_read, named.len() as u64);
        assert_eq!(
            totals.data_region_bytes,
            built.bytes.len() as u64 - DATA_REGION_OFFSET
        );
        // Two runs, one of a single wiped region and one of three, and the walk stepped through all
        // four of them.
        assert_eq!(totals.gaps, 2);
        assert_eq!(totals.unclaimed_regions, 4);
        assert_eq!(
            totals.unclaimed_bytes,
            built.gaps.iter().map(|(_, len)| len).sum::<u64>()
        );
        assert_eq!(totals.largest_gap, 8 * u64::from(DATA_UNIT));
        // Slack is what an archive that shrank a file in place leaves reserved inside a slot: the
        // fixture's 2, 8 and 4 units of it.
        assert_eq!(totals.slack_bytes, 14 * u64::from(DATA_UNIT));
        assert_eq!(
            totals.claimed_bytes + totals.unclaimed_bytes,
            totals.data_region_bytes
        );

        let decoded = walk(
            &built.bytes,
            &named,
            &SweepOptions {
                decode_entries: true,
                ..SweepOptions::default()
            },
        )
        .totals;
        assert_eq!(decoded.entries_decoded, named.len() as u64);
        let hashed = inspect_data_region(&headers(&built.bytes).dat.unwrap(), container()).totals;
        assert_eq!(hashed.bytes_hashed, totals.data_region_bytes);
        assert_eq!(hashed.unclaimed_hash_fields, 0);
    }

    #[test]
    fn a_container_with_no_magic_is_read_and_never_reported() {
        // Nineteen of a full install's eighty-six dat files carry no `SqPack` magic, and their own
        // digest covers the blob written over it. Refusing them, or checking a common header that is
        // not there, would report a fifth of a real install as broken.
        let mut b = clean_dat();
        b.no_magic();
        let built = b.built();
        let inspection = headers(&built.bytes);
        assert!(
            inspection.report.findings.is_empty(),
            "{:#?}",
            inspection.report.findings
        );
        assert!(
            inspection
                .dat
                .is_some_and(|dat| dat.common_header().is_none())
        );
        assert!(
            walk(
                &built.bytes,
                &located(&built.placed),
                &SweepOptions::default()
            )
            .findings
            .is_empty()
        );
    }

    #[test]
    fn a_data_region_digest_of_all_zeros_claims_nothing_and_is_counted_instead() {
        // Two dat files of a full install declare this, where a third empty archive declares the digest
        // of nothing. All zeros means unclaimed, so it is skipped rather than compared.
        let mut b = clean_dat();
        b.zero_data_sha1();
        let bytes = b.bytes();
        let report = inspect_data_region(&headers(&bytes).dat.unwrap(), container());
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        assert_eq!(report.totals.unclaimed_hash_fields, 1);
        assert_eq!(report.totals.bytes_hashed, 0);
    }

    #[test]
    fn an_empty_archives_dat_names_no_locations_and_has_no_unclaimed_space() {
        // Eight archives of a full install are this shape: a 2048-byte `dat0` declaring no data region
        // at all, which no location names. Its region is empty, so there is nothing unclaimed either.
        let bytes = DatBuilder::new().bytes();
        assert_eq!(bytes.len() as u64, DATA_REGION_OFFSET);
        assert!(headers(&bytes).report.findings.is_empty());
        let report = walk(&bytes, &[], &SweepOptions::default());
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        assert_eq!(report.totals.data_region_bytes, 0);
        assert_eq!(report.totals.gaps, 0);
    }

    #[test]
    fn a_wiped_region_no_location_names_is_unclaimed_space_and_not_a_fault() {
        // A dat whose entries were all deleted: the whole region is the chain a patcher left, and a
        // walk handed no locations accounts for it without reporting anything.
        let mut b = DatBuilder::new();
        b.gap_chain(&[4, 1]);
        let built = b.built();
        let report = walk(&built.bytes, &[], &SweepOptions::default());
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        assert_eq!(report.totals.gaps, 1);
        assert_eq!(report.totals.unclaimed_regions, 2);
        assert_eq!(report.totals.unclaimed_bytes, 5 * u64::from(DATA_UNIT));
        assert_eq!(report.totals.claimed_bytes, 0);
    }

    #[test]
    fn a_region_full_of_entries_no_location_names_is_one_finding() {
        // The other side of the same coin: an index that lost its entry table leaves a region nothing
        // claims, and what is in it is not what a patcher stamps over space it freed.
        let built = clean_dat().built();
        let found = walk(&built.bytes, &[], &SweepOptions::default()).findings;
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].site.offset, Some(DATA_REGION_OFFSET));
        assert!(matches!(
            found[0].defect,
            Defect::GapNotEmptyBlockChain { .. }
        ));
    }

    // --- the container could not be read ---

    #[test]
    fn a_container_cut_short_of_its_data_header_is_one_unreadable_finding() {
        let bytes = clean_dat().bytes();
        let inspection = headers(&bytes[..COMMON_HEADER_LEN + 8]);
        assert_eq!(inspection.report.findings.len(), 1);
        assert!(matches!(
            inspection.report.findings[0].defect,
            Defect::ContainerUnreadable {
                fault: ReadFault::Truncated,
                ..
            }
        ));
        assert_eq!(inspection.report.totals.containers_unreadable, 1);
        assert_eq!(inspection.report.totals.data_files, 1);
        assert!(inspection.dat.is_none());
    }

    // --- the hashes a container declares over its own bytes ---

    #[test]
    fn each_header_is_checked_against_the_digest_it_declares_over_itself() {
        for header in [HeaderId::Common, HeaderId::Second] {
            let mut b = clean_dat();
            b.self_hash(header, [0xAB; 20]);
            let finding = only_header_finding(&b.bytes());
            assert_eq!(
                finding.site.offset,
                Some((header.starts_at() + SELF_HASH_AT) as u64)
            );
            assert!(matches!(
                finding.defect,
                Defect::HeaderHashMismatch {
                    header: reported,
                    declared,
                    ..
                } if reported == header && declared == [0xAB; 20]
            ));
            // A container whose own account of its bytes differs is what a mod tool's coherent rewrite
            // leaves behind, so it is altered rather than damaged.
            assert_eq!(finding.severity(), Severity::Altered);
            assert_eq!(finding.scope(), Scope::Container);
        }
    }

    #[test]
    fn the_data_region_is_checked_against_the_digest_the_header_declares() {
        let mut b = clean_dat();
        b.data_sha1([0xCD; 20]);
        let bytes = b.bytes();
        // The headers are still right about themselves, so this is only reachable by reading the
        // region: the default pass says nothing.
        assert!(headers(&bytes).report.findings.is_empty());
        let report = inspect_data_region(&headers(&bytes).dat.unwrap(), container());
        assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
        assert_eq!(report.findings[0].site.offset, Some(DATA_REGION_OFFSET));
        assert!(matches!(
            report.findings[0].defect,
            Defect::DataRegionHashMismatch { declared, len, .. }
                if declared == [0xCD; 20] && len == bytes.len() as u64 - DATA_REGION_OFFSET
        ));

        // And the same the other way round: one byte of the region changed, the digest left alone.
        let mut bytes = clean_dat().bytes();
        let at = usize::try_from(DATA_REGION_OFFSET).unwrap() + 300;
        bytes[at] ^= 0x40;
        let report = inspect_data_region(&headers(&bytes).dat.unwrap(), container());
        assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
        assert_eq!(
            report.totals.bytes_hashed,
            bytes.len() as u64 - DATA_REGION_OFFSET
        );
    }

    #[test]
    fn the_two_runs_no_hash_covers_must_be_zero() {
        // These eighty-eight bytes are the only ones in a container that neither self hash reaches, in
        // a dat exactly as in an index, which is why they are the one place a direct zero check earns
        // its keep.
        for header in [HeaderId::Common, HeaderId::Second] {
            let at = header.starts_at() + SELF_HASH_AT + SELF_HASH_LEN;
            let mut b = clean_dat();
            b.header_pad(at + 4, &[1]);
            let finding = only_header_finding(&b.bytes());
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
        mutate: fn(&mut DatBuilder),
        word: HeaderWord,
        at: u64,
        declared: u32,
        expected: u32,
    }

    #[test]
    fn each_header_word_that_never_varies_is_checked() {
        // The data header carries no version word, so the four it does carry plus the common header's
        // two are the whole set. A dat's common header is judged only when it is there.
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
                name: "data header size",
                mutate: |b| {
                    b.header_pad(DATA_HEADER_SIZE_AT as usize, &bytes::write_u32_le(0x800));
                },
                word: HeaderWord::SecondHeaderSize,
                at: DATA_HEADER_SIZE_AT,
                declared: 0x800,
                expected: 0x400,
            },
            WordCase {
                name: "unclassified",
                mutate: |b| {
                    b.unclassified(17);
                },
                word: HeaderWord::DataUnclassified,
                at: DATA_UNCLASSIFIED_AT,
                declared: 17,
                expected: 16,
            },
            WordCase {
                name: "reserved 0",
                mutate: |b| {
                    b.reserved(0, 9);
                },
                word: HeaderWord::DataReserved0,
                at: DATA_RESERVED_AT[0],
                declared: 9,
                expected: 0,
            },
            WordCase {
                name: "reserved 1",
                mutate: |b| {
                    b.reserved(1, 3);
                },
                word: HeaderWord::DataReserved1,
                at: DATA_RESERVED_AT[1],
                declared: 3,
                expected: 0,
            },
            WordCase {
                name: "reserved 2",
                mutate: |b| {
                    b.reserved(2, 5);
                },
                word: HeaderWord::DataReserved2,
                at: DATA_RESERVED_AT[2],
                declared: 5,
                expected: 0,
            },
        ];
        for case in cases {
            let mut b = clean_dat();
            (case.mutate)(&mut b);
            let finding = only_header_finding(&b.bytes());
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
    fn the_declared_region_must_end_where_the_file_does() {
        let mut b = clean_dat();
        let real = clean_dat().bytes().len() as u64;
        let units = (real - DATA_REGION_OFFSET) / u64::from(DATA_UNIT);
        b.declared_units(u32::try_from(units).unwrap() + 1);
        let bytes = b.bytes();
        let finding = only_header_finding(&bytes);
        assert_eq!(finding.site.offset, Some(DATA_UNITS_AT));
        assert_eq!(
            finding.defect,
            Defect::DeclaredLength {
                declared: real + u64::from(DATA_UNIT),
                actual: real,
            }
        );
        // A region the file does not reach is not hashed: the difference has been reported once
        // already, and hashing what is there would only derive a second one from it.
        let report = inspect_data_region(&headers(&bytes).dat.unwrap(), container());
        assert!(report.findings.is_empty());
        assert_eq!(report.totals.bytes_hashed, 0);
    }

    // --- the entries the index named ---

    #[test]
    fn a_location_the_container_cannot_produce_a_header_for_is_a_finding() {
        let built = clean_dat().built();
        let mut named = located(&built.placed);
        let past_the_end = built.bytes.len() as u64 - 8;
        named.push(Located {
            dat: 0,
            offset: past_the_end,
            key: 0xBEEF,
        });
        // That location is inside the last slot, so nothing else about the walk changes.
        let found = walk(&built.bytes, &named, &SweepOptions::default()).findings;
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].site.offset, Some(past_the_end));
        assert_eq!(found[0].site.key, Some(0xBEEF));
        assert!(matches!(
            found[0].defect,
            Defect::EntryHeaderUnreadable {
                fault: ReadFault::Truncated,
                ..
            }
        ));
        assert_eq!(found[0].scope(), Scope::File);
    }

    #[test]
    fn an_entry_declaring_a_content_type_the_format_does_not_define_is_a_finding() {
        let mut b = DatBuilder::new();
        b.entry(EntrySpec::unknown_type(9));
        let built = b.built();
        let finding = only_walk_finding(
            &built.bytes,
            &located(&built.placed),
            &SweepOptions::default(),
        );
        assert_eq!(
            finding.defect,
            Defect::EntryContentTypeUnknown { declared: 9 }
        );
        assert_eq!(finding.site.offset, Some(built.placed[0].offset));
    }

    #[test]
    fn an_entry_header_that_is_not_a_whole_number_of_units_is_a_finding() {
        // A header length off the unit grid necessarily takes the slot after it off the grid too, so
        // the run that leaves behind is accounted for rather than judged: this asks for the slot map
        // alone.
        let mut b = DatBuilder::new();
        b.entry(EntrySpec::standard(vec![b"payload".to_vec()]));
        let built = b.built();
        let mut bytes = built.bytes.clone();
        let at = usize::try_from(built.placed[0].offset).unwrap();
        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(100));
        let opts = SweepOptions {
            gaps: GapPolicy::Skip,
            ..SweepOptions::default()
        };
        let finding = only_walk_finding(&bytes, &located(&built.placed), &opts);
        assert_eq!(
            finding.defect,
            Defect::EntryHeaderMisaligned { header_size: 100 }
        );
    }

    #[test]
    fn an_entry_may_not_store_more_than_its_slot_reserves() {
        let built = clean_dat().built();
        let mut bytes = built.bytes.clone();
        let at = usize::try_from(built.placed[0].offset).unwrap() + OCCUPIED_UNITS_AT;
        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(99));
        let finding = only_walk_finding(&bytes, &located(&built.placed), &SweepOptions::default());
        assert!(matches!(
            finding.defect,
            Defect::OccupiedExceedsAllocated {
                occupied_units: 99,
                ..
            }
        ));
        assert_eq!(finding.site.offset, Some(built.placed[0].offset));
    }

    #[test]
    fn a_slot_may_not_reach_into_the_next_entrys() {
        let mut b = DatBuilder::new();
        b.entry(EntrySpec::standard(vec![b"first".to_vec()]));
        b.entry(EntrySpec::standard(vec![b"second".to_vec()]));
        let built = b.built();
        let mut bytes = built.bytes.clone();
        let at = usize::try_from(built.placed[0].offset).unwrap() + ALLOCATED_UNITS_AT;
        let grown = u32_at(&bytes, at).unwrap() + 1;
        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(grown));
        let finding = only_walk_finding(&bytes, &located(&built.placed), &SweepOptions::default());
        // Filed against the slot that reaches too far, which is the entry a repair has to re-place.
        assert_eq!(finding.site.offset, Some(built.placed[0].offset));
        assert!(matches!(
            finding.defect,
            Defect::SlotsOverlap { next_offset, .. } if next_offset == built.placed[1].offset
        ));
    }

    #[test]
    fn one_slot_swallowing_several_entries_blames_only_itself() {
        // The entries a runaway slot covers are the right length themselves, so naming the one just
        // before each of them would send a repair after files that are not the fault, and would claim a
        // slot reaches past an entry it in fact ends exactly at.
        let mut b = DatBuilder::new();
        for payload in [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()] {
            b.entry(EntrySpec::standard(vec![payload]));
        }
        let built = b.built();
        let mut bytes = built.bytes.clone();
        let first = built.placed[0].offset;
        let last = built.placed[2].offset;
        let at = usize::try_from(first).unwrap() + ALLOCATED_UNITS_AT;
        // Reserve the distance to the last entry, so the slot ends one header past it and swallows both
        // of the others without running off the end of the declared region.
        let units = u32::try_from((last - first) / u64::from(DATA_UNIT)).unwrap();
        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(units));

        let found = walk(&bytes, &located(&built.placed), &SweepOptions::default()).findings;
        assert_eq!(found.len(), 2, "one per entry it swallowed: {found:#?}");
        for finding in &found {
            assert_eq!(finding.site.offset, Some(first));
        }
        assert!(matches!(
            found[1].defect,
            Defect::SlotsOverlap { next_offset, .. } if next_offset == last
        ));
    }

    #[test]
    fn an_entry_may_not_sit_in_the_containers_own_header() {
        // A coherent entry header written inside the second header, where the digest over `0x400..0x7C0`
        // still covers it: the only thing wrong is where the index says the entry is.
        let mut b = DatBuilder::new();
        b.entry(EntrySpec::standard(vec![b"payload".to_vec()]));
        let in_the_header = 0x700u64;
        let mut head = Vec::new();
        for word in [DATA_UNIT, ContentType::Empty.word(), 0, 0, 0] {
            head.extend_from_slice(&bytes::write_u32_le(word));
        }
        b.header_pad(usize::try_from(in_the_header).unwrap(), &head);
        let built = b.built();
        let mut named = located(&built.placed);
        named.insert(
            0,
            Located {
                dat: 0,
                offset: in_the_header,
                key: 0xF00D,
            },
        );
        let finding = only_walk_finding(&built.bytes, &named, &SweepOptions::default());
        assert_eq!(finding.defect, Defect::SlotBeforeDataRegion);
        assert_eq!(finding.site.offset, Some(in_the_header));
        assert_eq!(finding.site.key, Some(0xF00D));
    }

    #[test]
    fn two_entries_inside_the_containers_header_do_not_overlap_each_other() {
        // Neither slot reaches the data region, so neither reaches the other. Measuring an overlap
        // against how far the accounting has got instead would call the second of any two locations
        // below `0x800` an overlap of the first, and send a repair after the entry named in it.
        let mut b = DatBuilder::new();
        b.entry(EntrySpec::standard(vec![b"payload".to_vec()]));
        let mut head = Vec::new();
        for word in [DATA_UNIT, ContentType::Empty.word(), 0, 0, 0] {
            head.extend_from_slice(&bytes::write_u32_le(word));
        }
        let in_the_header = [0x600u64, 0x700];
        for at in in_the_header {
            b.header_pad(usize::try_from(at).unwrap(), &head);
        }
        let built = b.built();
        let mut named = located(&built.placed);
        for (i, at) in in_the_header.iter().enumerate() {
            named.insert(
                i,
                Located {
                    dat: 0,
                    offset: *at,
                    key: 0xF00D + i as u64,
                },
            );
        }
        let found = walk(&built.bytes, &named, &SweepOptions::default()).findings;
        assert_eq!(found.len(), in_the_header.len(), "{found:#?}");
        for (finding, at) in found.iter().zip(in_the_header) {
            assert_eq!(finding.defect, Defect::SlotBeforeDataRegion);
            assert_eq!(finding.site.offset, Some(at));
        }
    }

    #[test]
    fn a_slot_may_not_end_past_the_declared_region() {
        // The last entry in the region, so growing its slot reaches past the end of the container
        // rather than into space something else already accounts for.
        let mut b = DatBuilder::new();
        b.entry(EntrySpec::standard(vec![b"first".to_vec()]))
            .entry(EntrySpec::standard(vec![b"last".to_vec()]));
        let built = b.built();
        let mut bytes = built.bytes.clone();
        let last = built.placed.last().unwrap().offset;
        let at = usize::try_from(last).unwrap() + ALLOCATED_UNITS_AT;
        let grown = u32_at(&bytes, at).unwrap() + 4;
        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(grown));
        let finding = only_walk_finding(&bytes, &located(&built.placed), &SweepOptions::default());
        assert_eq!(finding.site.offset, Some(last));
        assert!(matches!(
            finding.defect,
            Defect::SlotBeyondDataRegion { region_end, .. }
                if region_end == built.bytes.len() as u64
        ));
    }

    #[test]
    fn a_slot_named_past_a_short_declared_region_accounts_for_nothing_outside_it() {
        // A `data_units` word declaring less than the file holds is what an append whose index write
        // landed and whose header write did not leaves behind, and the locations past the end of that
        // region still have their twenty bytes to read. Those bytes are not in the region, so measuring
        // a run up to one of them takes unclaimed space out of thin air.
        let mut items = DatBuilder::new();
        items
            .entry(EntrySpec::standard(vec![b"inside".to_vec()]))
            .gap_chain(&[1, 3])
            .entry(EntrySpec::standard(vec![b"past the end".to_vec()]));
        let built = items.built();
        let (gap_at, _) = built.gaps[0];
        // The region ends one wiped region into the run, so the second location is outside it and the
        // first of the run's regions is the whole of the unclaimed space there is.
        let region_end = gap_at + u64::from(DATA_UNIT);
        let mut b = items.clone();
        b.declared_units(
            u32::try_from((region_end - DATA_REGION_OFFSET) / u64::from(DATA_UNIT)).unwrap(),
        );
        let bytes = b.bytes();

        let named = located(&built.placed);
        let report = walk(&bytes, &named, &SweepOptions::default());
        let totals = report.totals;
        assert_eq!(totals.data_region_bytes, region_end - DATA_REGION_OFFSET);
        assert_eq!(
            totals.claimed_bytes + totals.unclaimed_bytes,
            totals.data_region_bytes
        );
        assert_eq!(totals.unclaimed_bytes, u64::from(DATA_UNIT));
        assert_eq!(totals.gaps, 1);
        assert_eq!(totals.unclaimed_regions, 1);
        // The slot outside the region is the whole of what is reported: nothing is said about the bytes
        // past the region, which are the ones a container declaring less than it holds is asking about.
        assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
        assert_eq!(report.findings[0].site.offset, Some(built.placed[1].offset));
        assert!(matches!(
            report.findings[0].defect,
            Defect::SlotBeyondDataRegion { region_end: end, .. } if end == region_end
        ));

        // And a container cut short of where a data region starts declares one that ends before it
        // begins. The walk has to hold a location inside that container's own header against a region
        // end below it and still close the accounting on an empty region.
        let in_the_header = 0x500u64;
        let mut head = Vec::new();
        for word in [DATA_UNIT, ContentType::Empty.word(), 0, 0, 0] {
            head.extend_from_slice(&bytes::write_u32_le(word));
        }
        let mut b = items.clone();
        b.header_pad(usize::try_from(in_the_header).unwrap(), &head);
        let cut = usize::try_from(DATA_REGION_OFFSET).unwrap() - 0x200;
        let named = [Located {
            dat: 0,
            offset: in_the_header,
            key: 0xF00D,
        }];
        let report = walk(&b.bytes()[..cut], &named, &SweepOptions::default());
        assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
        assert_eq!(report.findings[0].defect, Defect::SlotBeforeDataRegion);
        assert_eq!(report.totals.data_region_bytes, 0);
        assert_eq!(report.totals.claimed_bytes, 0);
        assert_eq!(report.totals.unclaimed_bytes, 0);
    }

    // --- the space between slots ---

    #[test]
    fn a_run_of_unclaimed_space_must_be_tiled_exactly_by_the_chain_a_patcher_stamps() {
        let built = clean_dat().built();
        let (gap_at, gap_len) = built.gaps[0];
        let at = usize::try_from(gap_at).unwrap();

        // Nothing a patcher would have written: the run is unaccounted for from its first byte.
        let mut bytes = built.bytes.clone();
        bytes[at..at + 4].copy_from_slice(&[0; 4]);
        let finding = only_walk_finding(&bytes, &located(&built.placed), &SweepOptions::default());
        assert_eq!(finding.site.offset, Some(gap_at));
        assert_eq!(
            finding.defect,
            Defect::GapNotEmptyBlockChain {
                len: gap_len,
                covered: 0,
                regions: 0,
            }
        );
        assert_eq!(finding.severity(), Severity::Altered);

        // A region claiming more than the run holds: the walk keeps what it stepped through and says
        // how far it got.
        let (chain_at, chain_len) = built.gaps[1];
        let mut bytes = built.bytes.clone();
        let second = usize::try_from(chain_at).unwrap() + 2 * DATA_UNIT as usize;
        bytes[second..second + EMPTY_BLOCK_HEADER_LEN].copy_from_slice(&empty_block_header(1000));
        let finding = only_walk_finding(&bytes, &located(&built.placed), &SweepOptions::default());
        assert_eq!(
            finding.defect,
            Defect::GapNotEmptyBlockChain {
                len: chain_len,
                covered: 2 * u64::from(DATA_UNIT),
                regions: 1,
            }
        );

        // The one count field that spells no region at all. A walk that read it as zero blocks would
        // never advance, so this is the anti-stall pin as much as it is a finding.
        let mut bytes = built.bytes.clone();
        bytes[at..at + EMPTY_BLOCK_HEADER_LEN].copy_from_slice(&empty_block_header(0));
        let finding = only_walk_finding(&bytes, &located(&built.placed), &SweepOptions::default());
        assert!(matches!(
            finding.defect,
            Defect::GapNotEmptyBlockChain {
                covered: 0,
                regions: 0,
                ..
            }
        ));

        // And under `Skip` none of the three is looked at: the space is counted, not read.
        let opts = SweepOptions {
            gaps: GapPolicy::Skip,
            ..SweepOptions::default()
        };
        let report = walk(&bytes, &located(&built.placed), &opts);
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        assert_eq!(report.totals.gaps, 2);
        assert_eq!(report.totals.unclaimed_regions, 0);
        assert_eq!(report.totals.unclaimed_bytes, gap_len + chain_len);
    }

    #[test]
    fn unclaimed_space_holding_something_else_is_reported_and_still_accounted_for() {
        let mut b = DatBuilder::new();
        b.entry(EntrySpec::standard(vec![b"payload".to_vec()]))
            .raw_gap(b"whatever was left here".to_vec());
        let built = b.built();
        let report = walk(
            &built.bytes,
            &located(&built.placed),
            &SweepOptions::default(),
        );
        assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
        assert_eq!(report.totals.unclaimed_bytes, u64::from(DATA_UNIT));
        assert_eq!(
            report.totals.claimed_bytes + report.totals.unclaimed_bytes,
            report.totals.data_region_bytes
        );
    }

    // --- extracting every entry ---

    #[test]
    fn an_entry_that_will_not_decode_is_a_finding_only_under_the_decode_pass() {
        let built = clean_dat().built();
        let mut bytes = built.bytes.clone();
        // A "compressed" size above the stored sentinel is a framing the codec refuses outright.
        let block_at = usize::try_from(built.placed[0].offset).unwrap() + DATA_UNIT as usize;
        bytes[block_at + 8..block_at + 12].copy_from_slice(&bytes::write_u32_le(0x8000));
        let named = located(&built.placed);
        assert!(
            walk(&bytes, &named, &SweepOptions::default())
                .findings
                .is_empty()
        );

        let opts = SweepOptions {
            decode_entries: true,
            ..SweepOptions::default()
        };
        let report = walk(&bytes, &named, &opts);
        assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
        assert_eq!(report.findings[0].site.offset, Some(built.placed[0].offset));
        assert!(matches!(
            report.findings[0].defect,
            Defect::EntryDecodeFailed {
                fault: ReadFault::BlockCorrupt,
                produced: 0,
                ..
            }
        ));
        assert_eq!(report.totals.entries_decoded, named.len() as u64 - 1);
    }

    // --- the budget ---

    #[test]
    fn the_budget_keeps_what_it_can_and_counts_the_rest() {
        let mut b = DatBuilder::new();
        for _ in 0..64 {
            b.entry(EntrySpec::unknown_type(9));
        }
        let built = b.built();
        let opts = SweepOptions {
            max_defects_per_container: 4,
            ..SweepOptions::default()
        };
        let report = walk(&built.bytes, &located(&built.placed), &opts);
        assert_eq!(report.findings.len(), 4);
        assert!(report.truncated);
        assert_eq!(report.totals.defects_suppressed, 60);
        // The walk was not cut short by the budget: everything it accounted for is still accounted for.
        assert_eq!(report.totals.entry_headers_read, 64);
    }

    // --- the layout the checks address by offset ---

    #[test]
    fn the_header_field_offsets_are_where_the_reader_reads_them() {
        // The parse takes the data header's fields in sequence; the checks name them by position.
        // These are the same bytes, and a divergence would file findings against the wrong words.
        let mut b = clean_dat();
        b.span_index(6).max_file_size(1234).unclassified(20);
        let bytes = b.bytes();
        let Some(dat) = headers(&bytes).dat else {
            panic!("the clean fixture must parse")
        };
        let header = dat.data_header();
        let at = |offset: u64| u32_at(&bytes, usize::try_from(offset).unwrap());
        assert_eq!(at(DATA_HEADER_SIZE_AT), Some(header.header_size));
        assert_eq!(at(DATA_UNCLASSIFIED_AT), Some(20));
        assert_eq!(at(DATA_UNITS_AT), Some(header.data_units));
        assert_eq!(at(DATA_HEADER_OFFSET + 0x10), Some(header.span_index));
        assert_eq!(at(DATA_HEADER_OFFSET + 0x18), Some(header.max_file_size));
        assert_eq!(
            crate::integrity::digest_at(
                &bytes,
                usize::try_from(DATA_HEADER_OFFSET).unwrap() + 0x20
            ),
            Some(header.data_sha1)
        );
        assert_eq!(
            header.data_sha1,
            sha1(&bytes[usize::try_from(DATA_REGION_OFFSET).unwrap()..])
        );
        // The reserved words are the ones the parse skips, so nothing carries them: a check has to read
        // them out of the bytes at these three positions.
        for at in DATA_RESERVED_AT {
            assert!(at > DATA_HEADER_OFFSET && at < DATA_HEADER_OFFSET + 0x20);
        }
        assert_eq!(ENTRY_HEADER_LEN, 0x14);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// No byte of a container can change unnoticed. Provable rather than hopeful: the two self
        /// hashes cover everything before them, the two 44-byte tails after them are checked zero, the
        /// digest fields themselves are what the comparison reads, and the data region is covered by
        /// the digest the header declares over it.
        #[test]
        fn no_byte_of_a_container_can_change_unnoticed(at in 0usize..0x4000, bit in 0u32..8) {
            let mut b = DatBuilder::new();
            b.entry(EntrySpec::standard(vec![b"the quick brown fox ".repeat(60)]));
            let built = b.built();
            let mut bytes = built.bytes.clone();
            let at = at % bytes.len();
            bytes[at] ^= 1 << bit;
            let mut found = headers(&bytes).report.findings;
            if let Some(dat) = headers(&bytes).dat {
                found.extend(inspect_data_region(&dat, container()).findings);
            }
            prop_assert!(!found.is_empty(), "byte {:#x} bit {} went unnoticed", at, bit);
        }

        /// The accounting closes for any shape, which is what makes a report honest about what it did
        /// not check: measured to hold exactly over a full install's 125,797,530,368 region bytes.
        #[test]
        fn the_space_accounting_closes(
            sizes in prop::collection::vec(0usize..3000, 0..8),
            slack in 0u32..4,
            gaps in prop::collection::vec(1u32..4, 0..4),
            overlap in any::<bool>(),
            shrink in 0u32..6,
        ) {
            let mut b = DatBuilder::new();
            b.slack(slack);
            for size in &sizes {
                b.entry(EntrySpec::standard(vec![vec![0x5A; *size]]));
            }
            for units in &gaps {
                b.gap(*units);
            }
            let built = b.built();
            // A region declared shorter than the file is what an interrupted header write leaves, and
            // the locations past its end are still readable: what the walk accounts for has to stay
            // inside the region it says it measured either way.
            let laid = (built.bytes.len() as u64 - DATA_REGION_OFFSET) / u64::from(DATA_UNIT);
            b.declared_units(u32::try_from(laid.saturating_sub(u64::from(shrink))).unwrap_or(0));
            let mut bytes = b.bytes();
            if overlap && let Some(first) = built.placed.first() {
                // Two slots covering the same bytes still has to balance, because claimed space is the
                // union of the slots rather than their sum.
                let at = usize::try_from(first.offset).unwrap() + ALLOCATED_UNITS_AT;
                let grown = u32_at(&bytes, at).unwrap_or(0) + 2;
                bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(grown));
            }
            for opts in every_pass() {
                let totals = walk(&bytes, &located(&built.placed), &opts).totals;
                prop_assert_eq!(
                    totals.claimed_bytes + totals.unclaimed_bytes,
                    totals.data_region_bytes
                );
            }
        }
    }
}
