//! The comparison: one data file's entries against what the map says its bytes should be.
//!
//! Pure over an injected [`DatSource`] and a [`Coverage`], so every rule below is reachable from a
//! byte slice and a hand-written map, with no filesystem and no patch anywhere near it.
//!
//! Two short circuits carry almost all of the work, and they are what makes the pristine gate
//! trivially true rather than expensively true:
//!
//! - a container the map vouches for end to end holds only pristine files, and **no byte of it is
//!   read**: not one entry header. A pristine install therefore classifies out of its indexes alone.
//! - a container in a repository the map does not claim exhaustively is judged by nobody, and is
//!   likewise never read. A map covering one repository leaves every other one here, so this is the
//!   arm the cost of the whole install would otherwise land on.
//!
//! What is left is the container something changed and the container the map never had, and there
//! the walk is the integrity sweep's: twenty bytes at each location an index named. The second of
//! those is already decided before the walk, and is walked anyway because a verdict names an extent
//! and only the entry knows it.

use crate::dat::DATA_REGION_OFFSET;
use crate::dat::{ContentType, Dat, DatSource, EntryHeader};
use crate::integrity::{ContainerRef, Located};
use crate::mods::map::{ByteRange, Coverage};
use crate::mods::verdict::{
    Confidence, ContainerStanding, ContainerVerdict, FileStanding, Standing,
};
use crate::mods::{ModOptions, ModTotals};

/// What comparing one container produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerComparison {
    /// Every file that is not pristine, in the order the locations were walked.
    pub files: Vec<FileStanding>,
    /// How the container itself stands.
    pub verdict: Option<ContainerVerdict>,
    /// What the comparison counted.
    pub totals: ModTotals,
    /// Whether the per-container budget filled, so the rest were counted rather than carried.
    pub truncated: bool,
}

/// What an entry occupies of its container's bytes, as the extraction reads it.
///
/// The header, then the data it stores. Not the slot: an entry reserves space it does not use, and
/// over a full retail install that surplus is 8.08 GB across 39% of the entries, so charging it to
/// the file would let a difference in bytes no extraction touches read as a changed file. The
/// declared occupancy is exact rather than merely safe here: measured over all 1,911,006 entries of
/// a retail install, the last byte any entry's block, mip or section table names lands exactly on
/// it, never past it and never short.
///
/// An [`ContentType::Empty`] entry is a placeholder whose remaining words are its previous
/// occupant's leftovers, so only its own header is claimed.
#[must_use]
pub fn content_extent(header: &EntryHeader, offset: u64) -> ByteRange {
    let len = match header.content_type {
        ContentType::Empty => u64::from(header.header_size),
        _ => u64::from(header.header_size).saturating_add(header.occupied_bytes()),
    };
    ByteRange::at(offset, len)
}

/// Compare the entries one data file holds against what the map says.
///
/// `named` must be ascending by offset and hold only this container's locations, which is what
/// [`crate::integrity::IndexInspection::locations`] gives after filtering on the data file.
/// `coverage` is what the map says about *this* container, and `accounted` whether the map claims to
/// describe its repository exhaustively; between them they decide what an absent description means.
#[must_use]
pub fn classify_entries<S: DatSource>(
    dat: &Dat<S>,
    named: &[Located],
    coverage: Option<&Coverage>,
    accounted: bool,
    at: ContainerRef,
    opts: &ModOptions,
) -> ContainerComparison {
    let mut out = ContainerComparison {
        totals: ModTotals {
            containers: 1,
            ..ModTotals::default()
        },
        ..ContainerComparison::default()
    };
    let actual_len = dat.len();

    let Some(coverage) = coverage else {
        // Nothing describes this container. Whether that means a mod tool made it or that the map
        // was never asked is the caller's claim to make, and the difference is the whole reason
        // `accounts_for` exists.
        if !accounted {
            out.verdict = Some(ContainerVerdict {
                container: at,
                standing: ContainerStanding::Unknown,
                pristine_len: None,
                actual_len: Some(actual_len),
            });
            // No read at all. Nothing is claimed about these entries, and the map covering one
            // repository leaves every other one here: reading a header apiece would put the cost of
            // the whole install on a pass that judges none of it.
            file_verdicts(&mut out, named, at, Standing::Unknown, opts);
            return out;
        }
        out.verdict = Some(ContainerVerdict {
            container: at,
            standing: ContainerStanding::Added,
            pristine_len: None,
            actual_len: Some(actual_len),
        });
        // The verdict follows from the container, but the extent does not, and a caller is owed
        // both: this is where a real mod tool's files land, and reporting them as zero bytes long
        // is the difference between "five files, 6.4 MB" and "five files" in the prompt they feed.
        // The walk is the same one a grown container gets, which is the same phenomenon written a
        // different way, and it is bounded by the entries the index sends into a container no patch
        // wrote.
        let region_end = dat.data_header().declared_file_len().min(actual_len);
        let extents = extents_of(dat, named, region_end, at, &mut out, opts);
        for (located, extent) in named.iter().zip(&extents) {
            let Some(extent) = *extent else {
                continue; // already filed as broken by the walk
            };
            push(
                &mut out,
                FileStanding {
                    container: at,
                    key: located.key,
                    offset: located.offset,
                    len: extent.len(),
                    standing: Standing::Foreign,
                    confidence: Confidence::Exact,
                },
                opts,
            );
        }
        return out;
    };

    out.verdict = Some(ContainerVerdict {
        container: at,
        standing: container_standing(coverage, actual_len),
        pristine_len: Some(coverage.pristine_len()),
        actual_len: Some(actual_len),
    });

    if coverage.vouches_whole(actual_len) {
        // The map answers for every byte, so every entry in it is pristine and none is read.
        out.totals.pristine += named.len() as u64;
        return out;
    }

    // The walk is clipped the way the integrity sweep clips it, so the two passes measure the same
    // region of the same container.
    let region_end = dat.data_header().declared_file_len().min(actual_len);
    let extents = extents_of(dat, named, region_end, at, &mut out, opts);
    let shared = shared_runs(coverage, &extents);

    for (located, extent) in named.iter().zip(&extents) {
        let Some(extent) = *extent else {
            continue; // already filed as broken by the walk
        };
        let (standing, confidence) = judge(coverage, extent, &shared);
        push(
            &mut out,
            FileStanding {
                container: at,
                key: located.key,
                offset: located.offset,
                len: extent.len(),
                standing,
                confidence,
            },
            opts,
        );
    }
    out
}

/// Read every named entry's header and reduce it to the bytes the entry is made of. `None` for an
/// entry already filed as broken.
fn extents_of<S: DatSource>(
    dat: &Dat<S>,
    named: &[Located],
    region_end: u64,
    at: ContainerRef,
    out: &mut ContainerComparison,
    opts: &ModOptions,
) -> Vec<Option<ByteRange>> {
    let mut extents = Vec::with_capacity(named.len());
    for located in named {
        let Ok(header) = dat.entry_header_at(located.offset) else {
            push(out, whole(located, at, Standing::Broken), opts);
            extents.push(None);
            continue;
        };
        out.totals.entry_headers_read += 1;
        let extent = content_extent(&header, located.offset);
        // An entry reaching outside the region its own container declares cannot be compared against
        // a map of that region: what it would deliver is not in there. The integrity sweep files the
        // same bytes as a defect of its own; the two reports explain them from different directions
        // and neither stands in for the other.
        if located.offset < DATA_REGION_OFFSET || extent.end > region_end {
            push(out, whole(located, at, Standing::Broken), opts);
            extents.push(None);
            continue;
        }
        extents.push(Some(extent));
    }
    extents
}

/// Which of the coverage's dirty runs touch more than one entry, as a parallel bitmap over
/// `coverage.dirty()`.
///
/// A run is as fine as whatever measured it. Over a real patch chain most writes are smaller than
/// one file, so most runs name one entry and the verdict is exact; the long tail is what this
/// answers, and a run in it makes every entry under it say so rather than accusing each alone.
fn shared_runs(coverage: &Coverage, extents: &[Option<ByteRange>]) -> Vec<bool> {
    let mut counts = vec![0u32; coverage.dirty().len()];
    for extent in extents.iter().flatten() {
        for count in &mut counts[coverage.dirty_span(*extent)] {
            *count = count.saturating_add(1);
        }
    }
    counts.into_iter().map(|n| n > 1).collect()
}

/// How one entry's bytes stand, and how exactly that names it.
fn judge(coverage: &Coverage, extent: ByteRange, shared: &[bool]) -> (Standing, Confidence) {
    // Bytes past the length the container should have are bytes no patch wrote. This is what an
    // appending mod tool leaves, and it rests on a length rather than on a run, so it is exact
    // however coarsely the runs were measured.
    if extent.end > coverage.pristine_len() {
        return (Standing::Foreign, Confidence::Exact);
    }
    let span = coverage.dirty_span(extent);
    if span.is_empty() {
        return (Standing::Pristine, Confidence::Exact);
    }
    let confidence = if shared[span].iter().any(|s| *s) {
        Confidence::Shared
    } else {
        Confidence::Exact
    };
    (Standing::Modified, confidence)
}

/// How the container itself stands, from its length and its runs alone.
fn container_standing(coverage: &Coverage, actual_len: u64) -> ContainerStanding {
    if actual_len > coverage.pristine_len() {
        ContainerStanding::Grown
    } else if actual_len < coverage.pristine_len() {
        ContainerStanding::Truncated
    } else if coverage.dirty().is_empty() {
        ContainerStanding::Pristine
    } else {
        ContainerStanding::Rewritten
    }
}

/// Give every location the same verdict, for a container nothing was read from.
///
/// Used where the answer follows from the container rather than from any entry: one the map never
/// described, and one that is not on disk at all.
pub(crate) fn file_verdicts(
    out: &mut ContainerComparison,
    named: &[Located],
    at: ContainerRef,
    standing: Standing,
    opts: &ModOptions,
) {
    for located in named {
        push(out, whole(located, at, standing), opts);
    }
}

/// A verdict over an entry nothing was read for: the whole slot is unknown, so the extent is zero
/// rather than a guess.
fn whole(located: &Located, container: ContainerRef, standing: Standing) -> FileStanding {
    FileStanding {
        container,
        key: located.key,
        offset: located.offset,
        len: 0,
        standing,
        confidence: Confidence::Exact,
    }
}

/// Count a verdict, and carry it unless it is pristine or the budget has filled.
///
/// Pristine files are counted and dropped: a full install holds 1.9 M of them and a caller asking
/// "what did a mod tool touch" wants the other list. The budget mirrors the integrity module's own,
/// for the same reason: a wrecked container otherwise names one verdict per entry.
fn push(out: &mut ContainerComparison, file: FileStanding, opts: &ModOptions) {
    match file.standing {
        Standing::Pristine => {
            out.totals.pristine += 1;
            return;
        }
        Standing::Modified => out.totals.modified += 1,
        Standing::Foreign => out.totals.foreign += 1,
        Standing::Broken => out.totals.broken += 1,
        Standing::Unknown => out.totals.unknown += 1,
    }
    if file.confidence == Confidence::Shared {
        out.totals.shared += 1;
    }
    if out.files.len() >= opts.max_files_per_container {
        out.totals.files_suppressed += 1;
        out.truncated = true;
        return;
    }
    out.files.push(file);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveId;
    use crate::dat::builder::{DatBuilder, EntrySpec};
    use crate::game::Repo;
    use crate::integrity::ContainerId;
    use crate::mods::map::PristineMap;

    fn at() -> ContainerRef {
        ContainerRef::new(Repo::Base, ArchiveId::new(0x0a, 0, 0), ContainerId::Dat(0))
    }

    /// A container holding four standard files, with where each landed.
    fn container() -> (Vec<u8>, Vec<(u64, u64)>) {
        let mut b = DatBuilder::new();
        for body in [
            b"first".repeat(40),
            b"second".repeat(400),
            b"third".repeat(40),
            b"fourth".repeat(40),
        ] {
            b.entry(EntrySpec::standard(vec![body]));
        }
        let built = b.built();
        let placed = built
            .placed
            .iter()
            .map(|p| (p.offset, p.content.len() as u64))
            .collect();
        (built.bytes, placed)
    }

    fn located(placed: &[(u64, u64)]) -> Vec<Located> {
        placed
            .iter()
            .enumerate()
            .map(|(i, (offset, _))| Located {
                dat: 0,
                offset: *offset,
                key: 0x1000 + i as u64,
            })
            .collect()
    }

    /// Classify a container against a map built by `describe`.
    fn run(
        bytes: &[u8],
        named: &[Located],
        describe: impl FnOnce(&mut crate::mods::map::MapBuilder),
    ) -> ContainerComparison {
        let mut builder = PristineMap::builder();
        builder.accounts_for(Repo::Base);
        describe(&mut builder);
        let map = builder.build();
        let dat = Dat::parse(bytes).unwrap();
        classify_entries(
            &dat,
            named,
            map.coverage(at()),
            map.accounts_for(Repo::Base),
            at(),
            &ModOptions::default(),
        )
    }

    #[test]
    fn a_container_the_map_vouches_for_is_all_pristine_and_never_read() {
        let (bytes, placed) = container();
        let named = located(&placed);
        let out = run(&bytes, &named, |b| {
            b.container(at(), bytes.len() as u64);
        });
        assert!(out.files.is_empty());
        assert_eq!(out.totals.pristine, 4);
        assert_eq!(out.totals.modified + out.totals.foreign, 0);
        // No entry header was read: the whole answer came from a length and an empty run list.
        assert_eq!(out.totals.entry_headers_read, 0);
        assert_eq!(out.verdict.unwrap().standing, ContainerStanding::Pristine);
    }

    #[test]
    fn a_dirty_run_inside_one_file_names_that_file_and_no_other() {
        let (bytes, placed) = container();
        let named = located(&placed);
        let (target, _) = placed[2];
        let out = run(&bytes, &named, |b| {
            b.container(at(), bytes.len() as u64)
                .dirty(at(), target + 128, 64);
        });
        assert_eq!(out.totals.pristine, 3);
        assert_eq!(out.files.len(), 1);
        assert_eq!(out.files[0].key, named[2].key);
        assert_eq!(out.files[0].standing, Standing::Modified);
        assert_eq!(out.files[0].confidence, Confidence::Exact);
        assert_eq!(out.totals.shared, 0);
        assert_eq!(out.verdict.unwrap().standing, ContainerStanding::Rewritten);
    }

    #[test]
    fn a_run_covering_several_files_says_so_rather_than_accusing_each_alone() {
        // A patch write is the unit a map measures at, and the long tail of real ones is larger than
        // one file. Every file under such a run gets the verdict and the caveat with it.
        let (bytes, placed) = container();
        let named = located(&placed);
        let out = run(&bytes, &named, |b| {
            b.container(at(), bytes.len() as u64).dirty(
                at(),
                placed[0].0,
                placed[2].0 - placed[0].0,
            );
        });
        assert_eq!(out.files.len(), 2);
        assert!(
            out.files
                .iter()
                .all(|f| f.standing == Standing::Modified && f.confidence == Confidence::Shared)
        );
        assert_eq!(out.totals.shared, 2);
        assert_eq!(out.totals.pristine, 2);
    }

    #[test]
    fn slack_inside_a_slot_is_not_part_of_the_file() {
        // 39% of a retail install's entries reserve space they do not store into, 8.08 GB of it. A
        // difference there changes nothing about what the entry extracts to, and charging it to the
        // file would report a modification that does not exist.
        let mut b = DatBuilder::new();
        b.slack(4)
            .entry(EntrySpec::standard(vec![b"body".repeat(40)]));
        let built = b.built();
        let placed = built.placed[0].clone();
        let named = vec![Located {
            dat: 0,
            offset: placed.offset,
            key: 7,
        }];
        let dat = Dat::parse(&built.bytes).unwrap();
        let header = dat.entry_header_at(placed.offset).unwrap();
        let extent = content_extent(&header, placed.offset);
        let slot_end = placed.offset + header.slot_len();
        assert!(extent.end < slot_end, "the fixture must reserve slack");

        let out = run(&built.bytes, &named, |b| {
            b.container(at(), built.bytes.len() as u64).dirty(
                at(),
                extent.end,
                slot_end - extent.end,
            );
        });
        assert_eq!(out.totals.pristine, 1);
        assert!(out.files.is_empty());
        // The container still says it was rewritten: the bytes did change, they are just not a file.
        assert_eq!(out.verdict.unwrap().standing, ContainerStanding::Rewritten);
    }

    #[test]
    fn an_entry_past_the_length_the_map_declares_is_foreign_exactly() {
        // The signature of every appending mod tool, and the one verdict that does not depend on how
        // finely the runs were measured: it comes from a length.
        let (bytes, placed) = container();
        let named = located(&placed);
        let out = run(&bytes, &named, |b| {
            b.container(at(), placed[2].0);
        });
        let foreign: Vec<_> = out
            .files
            .iter()
            .filter(|f| f.standing == Standing::Foreign)
            .collect();
        assert_eq!(foreign.len(), 2);
        assert!(foreign.iter().all(|f| f.confidence == Confidence::Exact));
        assert_eq!(out.totals.pristine, 2);
        assert_eq!(out.verdict.unwrap().standing, ContainerStanding::Grown);
    }

    #[test]
    fn a_data_file_the_map_never_had_is_wholly_foreign_and_says_how_long_each_file_is() {
        // The shape a real mod tool leaves: it writes a data file of its own and repoints the index
        // into it, rather than growing one the chain wrote. The container decides the verdict, so
        // nothing is read to reach it, but the extent is the entry's own and is read for.
        let (bytes, placed) = container();
        let named = located(&placed);
        let out = run(&bytes, &named, |_| {});
        assert_eq!(out.files.len(), 4);
        assert!(
            out.files
                .iter()
                .all(|f| f.standing == Standing::Foreign && f.confidence == Confidence::Exact)
        );
        assert_eq!(out.totals.entry_headers_read, 4);
        assert!(
            out.files.iter().all(|f| f.len > 0),
            "a file a repair would replace is not zero bytes long: {:?}",
            &out.files[..]
        );
        // The same extents the walk over a described container produces, entry for entry.
        let described = run(&bytes, &named, |b| {
            b.container(at(), bytes.len() as u64)
                .dirty(at(), 0, bytes.len() as u64);
        });
        let lengths: Vec<u64> = out.files.iter().map(|f| f.len).collect();
        let expected: Vec<u64> = described.files.iter().map(|f| f.len).collect();
        assert_eq!(lengths, expected);
        assert_eq!(out.verdict.unwrap().standing, ContainerStanding::Added);
    }

    #[test]
    fn an_unaccounted_repository_yields_unknown_rather_than_foreign() {
        // The guard that keeps a map covering one repository from calling every archive of the
        // others a mod tool's work.
        let (bytes, placed) = container();
        let named = located(&placed);
        let map = PristineMap::builder().build();
        let dat = Dat::parse(&bytes).unwrap();
        let out = classify_entries(&dat, &named, None, false, at(), &ModOptions::default());
        assert!(map.is_empty());
        assert_eq!(out.totals.unknown, 4);
        assert_eq!(out.totals.foreign, 0);
        assert!(out.files.iter().all(|f| !f.standing.repair_would_replace()));
        assert_eq!(out.verdict.unwrap().standing, ContainerStanding::Unknown);
    }

    #[test]
    fn the_budget_counts_what_it_drops() {
        let (bytes, placed) = container();
        let named = located(&placed);
        let mut builder = PristineMap::builder();
        builder.accounts_for(Repo::Base);
        let map = builder.build();
        let dat = Dat::parse(&bytes).unwrap();
        let out = classify_entries(
            &dat,
            &named,
            map.coverage(at()),
            true,
            at(),
            &ModOptions {
                max_files_per_container: 2,
                ..ModOptions::default()
            },
        );
        assert_eq!(out.files.len(), 2);
        assert!(out.truncated);
        assert_eq!(out.totals.files_suppressed, 2);
        // The counts are whole even where the list is not, which is what makes a truncated report
        // still able to say how many files a repair would replace.
        assert_eq!(out.totals.foreign, 4);
    }
}
