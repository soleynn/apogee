//! The whole-install sweep: the pure per-container checks driven over every archive a game tree holds.
//!
//! One archive is the unit of work, and the archives run in parallel, because the cost is spread very
//! unevenly: the largest single data file of a real install is an eighth of it, so an archive's data
//! files run in parallel too rather than serialising behind each other.
//!
//! The sweep opens containers directly instead of going through the handle's caches, so a report does
//! not leave fifty megabytes of parsed indexes and every data file's handle behind in a handle the
//! caller goes on using.

use std::collections::BTreeSet;

use rayon::prelude::*;

use super::finding::read_fault;
use crate::dat::FileSource;
use crate::game::{ArchiveInfo, GameData};
use crate::index::{self, IndexKind};
use crate::integrity::{
    ContainerId, ContainerRef, ContainerReport, Defect, Finding, IndexFacts, Located, Report, Site,
    SweepOptions, Totals, compare_index_forms, inspect_dat_entries, inspect_dat_headers,
    inspect_data_region, inspect_index,
};

/// The most data files an archive can be missing one of. A location word spells the data file in three
/// bits, so nothing an index names can be above this, and a declared count above it has already been
/// reported as one that disagrees with the directory.
const MAX_DATA_FILES: u32 = 8;

impl GameData {
    /// Sweep this install's SqPack containers and report what is structurally wrong with them.
    ///
    /// Infallible on purpose: the tree is the subject here, so a container that will not open is a
    /// finding rather than a reason to abandon a sweep over a hundred gigabytes. A caller telling a
    /// broken install apart from a broken disk reads [`Totals::containers_unreadable`].
    #[must_use]
    pub fn inspect(&self, opts: &SweepOptions) -> Report {
        let archives = self.archives();
        let reports = in_pool(opts, || {
            archives
                .par_iter()
                .map(|info| self.archive_report(info, opts))
                .collect::<Vec<_>>()
        });
        // Merged in archive order and sorted once at the end, so the report is a pure function of the
        // tree and the options rather than of the order the workers finished in.
        let mut out = Report::default();
        for report in reports {
            merge(&mut out, report);
        }
        settle(&mut out);
        out
    }

    /// Sweep one archive. This is the sweep's unit of work, and the seam a caller uses to drive it in
    /// pieces it can abandon between.
    #[must_use]
    pub fn inspect_archive(&self, info: &ArchiveInfo, opts: &SweepOptions) -> Report {
        let mut out = in_pool(opts, || self.archive_report(info, opts));
        settle(&mut out);
        out
    }

    /// One archive's report, in whatever thread pool is already installed.
    fn archive_report(&self, info: &ArchiveInfo, opts: &SweepOptions) -> Report {
        let archive = ContainerRef::new(info.repo, info.id, ContainerId::Archive);
        let mut out = Report {
            totals: Totals {
                archives: 1,
                ..Totals::default()
            },
            ..Report::default()
        };

        let forms = [IndexKind::Index1, IndexKind::Index2]
            .map(|kind| self.inspect_form(info, kind, archive, opts, &mut out));

        // Only worth comparing when both forms parsed: an unreadable container names no locations at
        // all, and reporting every location of the other form as unmatched would bury what went wrong.
        if let [Some(first), Some(second)] = &forms {
            absorb(
                &mut out,
                archive,
                compare_index_forms(&first.locations, &second.locations, archive, opts),
            );
        }
        let declared = forms
            .iter()
            .flatten()
            .map(|form| form.data_file_count)
            .max()
            .unwrap_or(0);

        // The primary form is the `.index` when it parsed, mirroring `lookup` and halving the random
        // reads. That the other form names the same places is what the comparison above has said, and
        // its locations are the only thing the comparison was for: an archive names millions of them, so
        // the walk below is left holding one form's rather than both.
        let [first, second] = forms;
        let locations = first
            .or(second)
            .map_or_else(Vec::new, |form| form.locations);

        // Both forms name their own locations, so what the walk was handed is the primary form's count
        // rather than the sum: the other form's is what the comparison above already spoke for.
        out.totals.locations = locations.len() as u64;

        let present: BTreeSet<u8> = info.dats.iter().copied().collect();
        let mut wanted: BTreeSet<u8> = (0..declared.min(MAX_DATA_FILES)).map(|n| n as u8).collect();
        wanted.extend(locations.iter().map(|located| located.dat));
        for dat in wanted.difference(&present) {
            out.findings.push(Finding {
                site: site(archive),
                defect: Defect::DataFileMissing { dat: *dat },
            });
        }

        let reports: Vec<Report> = info
            .dats
            .par_iter()
            .map(|dat| inspect_dat_file(info, *dat, &locations, archive, opts))
            .collect();
        for report in reports {
            merge(&mut out, report);
        }
        out
    }

    /// One index form of an archive: read whole, checked, and reduced to what the rest of the archive's
    /// checks read of it. `None` when the archive has no such form or it would not parse.
    fn inspect_form(
        &self,
        info: &ArchiveInfo,
        kind: IndexKind,
        archive: ContainerRef,
        opts: &SweepOptions,
        out: &mut Report,
    ) -> Option<Form> {
        let at = archive.with_file(ContainerId::Index(kind));
        if !info.has_index(kind) {
            out.findings.push(Finding {
                site: site(archive),
                defect: Defect::IndexFormMissing { kind },
            });
            return None;
        }
        let bytes = match index::read_capped(&info.index_path(kind), &opts.index_limits) {
            Ok(bytes) => bytes,
            Err(error) => {
                absorb(out, at, unreadable(at, &error));
                return None;
            }
        };
        let facts = IndexFacts {
            container: at,
            named: kind,
            dats: &info.dats,
        };
        let mut inspection = inspect_index(&bytes, &facts, opts);
        absorb(out, at, std::mem::take(&mut inspection.report));
        let data_file_count = inspection.index?.header().data_file_count;
        Some(Form {
            locations: inspection.locations,
            data_file_count,
        })
    }
}

/// One index form's inspection, as much of it as the archive's remaining checks read.
///
/// The parsed container is not among them: an index at the reader's cap parses to tens of millions of
/// entries, and one header word is all the sweep takes from them once the locations have been derived,
/// so it is dropped where it was parsed rather than held through the data-file walk.
struct Form {
    /// Every location the container names, ascending.
    locations: Vec<Located>,
    /// How many data files its header declares.
    data_file_count: u32,
}

/// One data file: its headers, then whichever of the two expensive passes were asked for.
fn inspect_dat_file(
    info: &ArchiveInfo,
    dat: u8,
    locations: &[Located],
    archive: ContainerRef,
    opts: &SweepOptions,
) -> Report {
    let at = archive.with_file(ContainerId::Dat(dat));
    let mut out = Report::default();
    let source = match FileSource::open(info.dat_path(dat)) {
        Ok(source) => source,
        Err(error) => {
            absorb(&mut out, at, unreadable(at, &error));
            return out;
        }
    };

    let inspection = inspect_dat_headers(source, at, opts);
    absorb(&mut out, at, inspection.report);
    let Some(container) = inspection.dat else {
        return out;
    };
    if opts.hash_data_regions {
        absorb(&mut out, at, inspect_data_region(&container, at));
    }
    if opts.walk_entries || opts.decode_entries {
        let named = locations_in(locations, dat);
        absorb(
            &mut out,
            at,
            inspect_dat_entries(&container, named, at, opts),
        );
    }
    out
}

/// Run `work` under the caller's thread-count cap. A pool that will not build is not worth abandoning a
/// sweep over, so the global one carries it instead.
fn in_pool<T: Send>(opts: &SweepOptions, work: impl FnOnce() -> T + Send) -> T {
    match opts.parallelism {
        Some(n) => match rayon::ThreadPoolBuilder::new().num_threads(n).build() {
            Ok(pool) => pool.install(work),
            Err(_) => work(),
        },
        None => work(),
    }
}

/// A container that would not open, as the one finding that is all anybody knows about it. Which
/// counter it is charged to comes from the site, so the count of containers reached stays right whether
/// or not any of them answered.
fn unreadable(at: ContainerRef, error: &crate::Error) -> ContainerReport {
    let (fault, detail, offset) = read_fault(error);
    let mut totals = Totals {
        containers_unreadable: 1,
        ..Totals::default()
    };
    match at.file {
        ContainerId::Index(_) => totals.index_files = 1,
        ContainerId::Dat(_) => totals.data_files = 1,
        _ => {}
    }
    ContainerReport {
        findings: vec![Finding {
            site: Site {
                container: at,
                offset,
                key: None,
            },
            defect: Defect::ContainerUnreadable { fault, detail },
        }],
        totals,
        truncated: false,
    }
}

/// A site that is the archive rather than any one of its files.
fn site(archive: ContainerRef) -> Site {
    Site {
        container: archive,
        offset: None,
        key: None,
    }
}

/// Fold one container's report into the archive's, remembering a container whose budget filled.
fn absorb(out: &mut Report, at: ContainerRef, report: ContainerReport) {
    out.findings.extend(report.findings);
    out.totals.merge(&report.totals);
    if report.truncated {
        out.truncated.push(at);
    }
}

/// Fold one archive's report into the sweep's.
fn merge(out: &mut Report, report: Report) {
    out.findings.extend(report.findings);
    out.totals.merge(&report.totals);
    out.truncated.extend(report.truncated);
}

/// Put a report into the order its documentation promises.
fn settle(out: &mut Report) {
    out.findings.sort_unstable();
    out.truncated.sort_unstable();
    out.truncated.dedup();
}

/// The stretch of `locations` naming one data file. Sorted by `(dat, offset, key)`, so this is two
/// boundaries rather than a filter over millions of entries.
fn locations_in(locations: &[Located], dat: u8) -> &[Located] {
    let start = locations.partition_point(|located| located.dat < dat);
    let end = locations.partition_point(|located| located.dat <= dat);
    locations.get(start..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveId;
    use crate::bytes;
    use crate::dat::builder::EntrySpec;
    use crate::game::Repo;
    use crate::index::Index;
    use crate::integrity::fixture::ArchiveFixture;
    use crate::integrity::{GapPolicy, Severity};
    use std::path::PathBuf;

    /// Two clean archives holding different files, in different repositories, which is the smallest
    /// tree that exercises everything the sweep itself does: two forms per archive, several data files
    /// per archive, and archives that must not be confused with each other.
    fn archives() -> Vec<ArchiveFixture> {
        let mut other = ArchiveFixture::clean(Repo::Ex(1), ArchiveId::new(0x02, 1, 1));
        other
            .file(
                0,
                "bg/ex1/01_roc_r2/twn/r2t1/level/planmap.lgb",
                EntrySpec::standard(vec![b"PLANMAP".repeat(30)]),
            )
            .file(
                1,
                "bg/ex1/01_roc_r2/twn/r2t1/level/bg.lgb",
                EntrySpec::standard(vec![b"BG".repeat(70)]),
            );
        vec![
            ArchiveFixture::clean(Repo::Base, ArchiveId::new(0x0a, 0, 0)),
            other,
        ]
    }

    /// Lay the fixtures out as a game tree and open it.
    fn tree(archives: &[ArchiveFixture]) -> (tempfile::TempDir, GameData) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("ffxivgame.ver"), "2026.07.16.0001.0000").unwrap();
        for fixture in archives {
            fixture.write_to(&repo_dir(tmp.path(), fixture)).unwrap();
        }
        let game = GameData::open(tmp.path()).unwrap();
        (tmp, game)
    }

    fn repo_dir(game: &std::path::Path, fixture: &ArchiveFixture) -> PathBuf {
        let (repo, _) = fixture.id();
        game.join("sqpack").join(repo.dir_name())
    }

    /// The file one of a fixture's containers was written to.
    fn file_in(game: &std::path::Path, fixture: &ArchiveFixture, name: &str) -> PathBuf {
        repo_dir(game, fixture).join(name)
    }

    fn every_pass() -> [SweepOptions; 4] {
        [
            SweepOptions::default(),
            SweepOptions {
                gaps: GapPolicy::Skip,
                walk_entries: false,
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

    /// The slugs a report carries, sorted and deduplicated, which is what a case about which checks
    /// fired asserts against.
    fn slugs(report: &Report) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = report.findings.iter().map(Finding::slug).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    // --- the gate: a clean tree produces nothing at all ---

    #[test]
    fn a_clean_install_yields_no_findings_under_any_pass() {
        let fixtures = archives();
        let (_tmp, game) = tree(&fixtures);
        for opts in every_pass() {
            let report = game.inspect(&opts);
            assert!(report.is_clean(), "{:#?}", report.findings);
            assert!(report.truncated.is_empty());
            assert_eq!(report.worst_severity(), None);
            assert_eq!(report.totals.archives, 2);
            assert_eq!(report.totals.index_files, 4);
            assert_eq!(report.totals.data_files, 4);
            assert_eq!(report.totals.containers_unreadable, 0);
        }
    }

    #[test]
    fn a_clean_install_accounts_for_every_container_it_read() {
        let fixtures = archives();
        let (_tmp, game) = tree(&fixtures);
        let built: Vec<_> = fixtures.iter().map(ArchiveFixture::built).collect();

        // What the fixtures laid down, derived from their own bytes rather than written out here: a
        // hardcoded count would only pin the fixture against itself.
        let forms = || {
            built
                .iter()
                .flat_map(|archive| [&archive.index1, &archive.index2])
        };
        let parsed = || forms().map(|bytes| Index::parse(bytes).unwrap());
        let index_bytes: u64 = forms().map(|bytes| bytes.len() as u64).sum();
        let entries: u64 = parsed().map(|index| index.entries().len() as u64).sum();
        let records: u64 = parsed().map(|index| index.collisions().len() as u64).sum();
        // The walk is handed the primary form's locations, which is the `.index`'s.
        let locations: u64 = built
            .iter()
            .map(|archive| {
                let index = Index::parse(&archive.index1).unwrap();
                (index.entries().iter().filter(|e| !e.is_collision()).count()
                    + index.collisions().len()) as u64
            })
            .sum();
        let region: u64 = built
            .iter()
            .flat_map(|archive| &archive.dats)
            .map(|dat| dat.bytes.len() as u64 - crate::dat::DATA_HEADER_OFFSET - 0x400)
            .sum();
        let unclaimed: u64 = built
            .iter()
            .flat_map(|archive| &archive.dats)
            .flat_map(|dat| &dat.gaps)
            .map(|(_, len)| len)
            .sum();

        let totals = game.inspect(&SweepOptions::default()).totals;
        assert_eq!(totals.index_bytes, index_bytes);
        assert_eq!(totals.entries, entries);
        assert_eq!(totals.collision_records, records);
        assert_eq!(totals.locations, locations);
        assert_eq!(totals.entry_headers_read, locations);
        assert_eq!(totals.data_region_bytes, region);
        assert_eq!(totals.unclaimed_bytes, unclaimed);
        assert_eq!(totals.claimed_bytes + totals.unclaimed_bytes, region);
        // One run of a single wiped region in one data file of each archive, and one run of three in
        // the other: the chain is one run, which is why the largest is its whole eight units.
        assert_eq!(totals.gaps, 4);
        assert_eq!(totals.unclaimed_regions, 8);
        assert_eq!(totals.largest_gap, 8 * u64::from(crate::dat::DATA_UNIT));
        assert_eq!(totals.unclaimed_hash_fields, 0);

        let deep = game.inspect(&SweepOptions {
            hash_data_regions: true,
            decode_entries: true,
            ..SweepOptions::default()
        });
        assert_eq!(deep.totals.entries_decoded, locations);
        // Every byte of every container: both headers of each, each index's four segments, and each
        // data file's whole region.
        assert!(deep.totals.bytes_hashed > region);
    }

    #[test]
    fn one_archive_can_be_swept_on_its_own() {
        // The seam a caller uses to drive a hundred gigabytes in pieces it can abandon between.
        let fixtures = archives();
        let (_tmp, game) = tree(&fixtures);
        let (repo, id) = fixtures[0].id();
        let info = game.archive(repo, id).unwrap();
        let report = game.inspect_archive(info, &SweepOptions::default());
        assert!(report.is_clean(), "{:#?}", report.findings);
        assert_eq!(report.totals.archives, 1);
        assert_eq!(report.totals.index_files, 2);
        assert_eq!(report.totals.data_files, 2);
    }

    #[test]
    fn a_tree_holding_no_archives_is_swept_and_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        let game = GameData::open(tmp.path()).unwrap();
        let report = game.inspect(&SweepOptions::default());
        assert!(report.is_clean());
        assert_eq!(report.totals, Totals::default());
    }

    // --- the report is a function of the tree, not of the schedule ---

    #[test]
    fn the_same_tree_reports_the_same_thing_at_any_thread_count() {
        let mut fixtures = archives();
        // Break something in every container class, so the comparison is over a report with content.
        fixtures[0].dat(0).zero_data_sha1().reserved(1, 7);
        let (tmp, game) = tree(&fixtures);
        std::fs::remove_file(file_in(
            tmp.path(),
            &fixtures[1],
            &fixtures[1].id().1.dat_file_name(1),
        ))
        .unwrap();
        let game = GameData::open(game.game_dir()).unwrap();

        let opts = |parallelism| SweepOptions {
            parallelism,
            hash_data_regions: true,
            ..SweepOptions::default()
        };
        let one = game.inspect(&opts(Some(1)));
        assert!(!one.is_clean());
        assert_eq!(one, game.inspect(&opts(Some(8))));
        assert_eq!(one, game.inspect(&opts(None)));
        assert_eq!(one, game.inspect(&opts(Some(1))));
        // Ascending by container, so a caller reading the list reads it archive by archive.
        assert!(
            one.findings
                .windows(2)
                .all(|pair| pair[0].site.container <= pair[1].site.container)
        );
    }

    #[test]
    fn adding_a_pass_only_adds_findings() {
        let mut fixtures = archives();
        fixtures[0].dat(1).data_sha1([0x11; 20]);
        let (tmp, game) = tree(&fixtures);
        // A payload the codec refuses, which only the decode pass reads.
        let path = file_in(
            tmp.path(),
            &fixtures[0],
            &fixtures[0].id().1.dat_file_name(0),
        );
        let mut bytes = std::fs::read(&path).unwrap();
        let block_at = usize::try_from(crate::dat::DATA_HEADER_OFFSET).unwrap() + 0x400 + 128;
        bytes[block_at + 8..block_at + 12].copy_from_slice(&bytes::write_u32_le(0x8000));
        std::fs::write(&path, &bytes).unwrap();
        let game = GameData::open(game.game_dir()).unwrap();

        let cheapest = game.inspect(&SweepOptions {
            walk_entries: false,
            gaps: GapPolicy::Skip,
            ..SweepOptions::default()
        });
        let default = game.inspect(&SweepOptions::default());
        let deep = game.inspect(&SweepOptions {
            hash_data_regions: true,
            decode_entries: true,
            ..SweepOptions::default()
        });
        assert!(cheapest.is_clean());
        assert!(default.is_clean());
        assert_eq!(
            slugs(&deep),
            ["data-region-hash-mismatch", "entry-decode-failed"]
        );
    }

    // --- the archive's files against each other ---

    #[test]
    fn an_archive_missing_an_index_form_is_reported_against_the_archive() {
        let fixtures = archives();
        let (tmp, game) = tree(&fixtures);
        let id = fixtures[0].id().1;
        std::fs::remove_file(file_in(
            tmp.path(),
            &fixtures[0],
            &id.index_file_name(IndexKind::Index2),
        ))
        .unwrap();
        let game = GameData::open(game.game_dir()).unwrap();
        let report = game.inspect(&SweepOptions::default());
        assert_eq!(
            report.findings.iter().map(|f| f.defect).collect::<Vec<_>>(),
            [Defect::IndexFormMissing {
                kind: IndexKind::Index2
            }]
        );
        assert_eq!(report.findings[0].site.container.file, ContainerId::Archive);
        assert_eq!(report.worst_severity(), Some(Severity::Unusable));
        // The archive is still swept: one form is enough to walk its data files.
        assert_eq!(report.totals.index_files, 3);
        assert_eq!(report.totals.data_files, 4);
    }

    #[test]
    fn a_data_file_the_archive_declares_but_does_not_have_is_reported() {
        let fixtures = archives();
        let (tmp, game) = tree(&fixtures);
        let id = fixtures[0].id().1;
        std::fs::remove_file(file_in(tmp.path(), &fixtures[0], &id.dat_file_name(1))).unwrap();
        let game = GameData::open(game.game_dir()).unwrap();
        let report = game.inspect(&SweepOptions::default());
        // Once for the file that is not there, and once per form for the count each still declares.
        // Which of the two is wrong is not decided here, which is why both are said.
        assert_eq!(slugs(&report), ["data-file-missing", "declared-dat-count"]);
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.slug() == "declared-dat-count")
                .count(),
            2
        );
        assert_eq!(report.totals.data_files, 3);
    }

    #[test]
    fn the_two_forms_of_an_archive_must_name_the_same_locations() {
        // An `.index2` for the same archive naming somewhere else: both forms parse and both are
        // coherent, and between them they name bytes the other does not. The second file sits past
        // everything the first form names, so the disagreement is reported in both directions.
        let fixtures = archives();
        let (tmp, game) = tree(&fixtures);
        let (repo, id) = fixtures[0].id();
        let mut moved = ArchiveFixture::new(repo, id, 2);
        moved
            .file(
                0,
                "exd/root.exl",
                EntrySpec::standard(vec![b"ROOT".to_vec()]),
            )
            .gap(1, 200)
            .file(
                1,
                "exd/elsewhere.exl",
                EntrySpec::standard(vec![b"ELSE".to_vec()]),
            );
        let name = id.index_file_name(IndexKind::Index2);
        std::fs::write(
            file_in(tmp.path(), &fixtures[0], &name),
            &moved.built().index2,
        )
        .unwrap();
        let game = GameData::open(game.game_dir()).unwrap();
        let report = game.inspect(&SweepOptions::default());
        assert_eq!(slugs(&report), ["forms-disagree"]);
        // Reported in both directions, against whichever form holds the location the other lacks.
        for kind in [IndexKind::Index1, IndexKind::Index2] {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|f| f.site.container.file == ContainerId::Index(kind)),
                "{kind:?}"
            );
        }
        assert_eq!(
            report.of_scope(crate::integrity::Scope::Archive).count(),
            report.findings.len()
        );

        // Under a budget the disagreement outgrows, the archive is named as a container whose checks
        // stopped and the rest are counted. Those two are all a caller has to size how much of a report
        // is missing, so a comparison that reported nothing dropped while naming the archive would say
        // the report is whole and cut short at once.
        let cap = report.findings.len() / 2;
        let capped = game.inspect(&SweepOptions {
            max_defects_per_container: cap,
            ..SweepOptions::default()
        });
        assert_eq!(capped.findings.len(), cap);
        assert_eq!(
            capped.truncated,
            [ContainerRef::new(repo, id, ContainerId::Archive)]
        );
        assert_eq!(
            capped.totals.defects_suppressed as usize,
            report.findings.len() - cap
        );
    }

    // --- a container that will not open is output, not a reason to stop ---

    #[test]
    fn a_container_that_will_not_parse_does_not_stop_the_sweep() {
        let fixtures = archives();
        let (tmp, game) = tree(&fixtures);
        let id = fixtures[0].id().1;
        // One cut mid-segment, one cut inside its own data header: neither can say anything about
        // itself, which is the whole of what is reported about them.
        for (name, cut) in [
            (id.index_file_name(IndexKind::Index1), None),
            (id.dat_file_name(0), Some(0x420)),
        ] {
            let path = file_in(tmp.path(), &fixtures[0], &name);
            let bytes = std::fs::read(&path).unwrap();
            let cut = cut.unwrap_or(bytes.len() / 2);
            std::fs::write(&path, &bytes[..cut]).unwrap();
        }
        let game = GameData::open(game.game_dir()).unwrap();
        let report = game.inspect(&SweepOptions::default());
        assert_eq!(report.totals.containers_unreadable, 2);
        // A caller comparing this with the container count is looking at a disconnected disk rather
        // than a corrupt install, which is what the counter is for.
        assert!(
            report.totals.containers_unreadable
                < report.totals.index_files + report.totals.data_files
        );
        // The other archive is untouched, and the surviving form of this one still says what it can.
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.site.container.archive == id)
        );
        assert!(slugs(&report).contains(&"container-unreadable"));

        let clean = game
            .archive(fixtures[1].id().0, fixtures[1].id().1)
            .unwrap();
        assert!(
            game.inspect_archive(clean, &SweepOptions::default())
                .is_clean()
        );
    }

    #[test]
    fn a_sweep_leaves_nothing_behind_in_the_handle_it_was_driven_from() {
        // A hundred gigabytes' worth of parsed indexes and open data files would otherwise sit in a
        // handle the caller goes on using.
        let fixtures = archives();
        let (_tmp, game) = tree(&fixtures);
        assert!(game.inspect(&SweepOptions::default()).is_clean());
        assert_eq!(game.cached_index_count(), 0);
        assert_eq!(game.cached_dat_count(), 0);
    }
}
