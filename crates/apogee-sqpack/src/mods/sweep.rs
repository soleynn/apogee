//! Driving the comparison over a whole install: the same shape [`crate::integrity`]'s sweep has, for
//! the same reasons. One archive is the unit of work and the archives run in parallel, because a
//! single data file of a real install can be an eighth of it.
//!
//! Where this differs from the structural sweep is what it costs. Both parse every index; that one
//! then reads every entry header of the install, while this one reads none at all in a container the
//! map already answers for, so what it adds on top of the indexes tracks how much of the install
//! disagrees rather than how large it is.

use std::collections::BTreeSet;

use rayon::prelude::*;

use crate::game::{ArchiveInfo, GameData};
use crate::index::{self, IndexKind};
use crate::integrity::{
    ContainerId, ContainerRef, IndexFacts, Located, SweepOptions, inspect_index,
};
use crate::mods::classify::{ContainerComparison, classify_entries, file_verdicts};
use crate::mods::map::{Coverage, PristineMap};
use crate::mods::verdict::{ContainerStanding, ContainerVerdict, Standing};
use crate::mods::{ModOptions, ModReport, ModTotals};

impl GameData {
    /// Compare this install against a map of what a pristine one holds.
    ///
    /// Infallible on purpose, like the structural sweep: the tree is the subject, so a container
    /// that will not open is a counted fact rather than a reason to abandon the comparison. A caller
    /// checks [`ModReport::is_exhaustive`] before reading a clean result as "no mods".
    #[must_use]
    pub fn detect_mods(&self, map: &PristineMap, opts: &ModOptions) -> ModReport {
        let reports: Vec<ModReport> = self
            .archives()
            .par_iter()
            .map(|info| self.compare_archive(info, map, opts))
            .collect();
        let mut out = ModReport::default();
        for report in reports {
            merge(&mut out, report);
        }
        settle(&mut out);
        out
    }

    /// Compare one archive. The seam a caller uses to drive an install in pieces it can abandon
    /// between, matching [`GameData::inspect_archive`].
    #[must_use]
    pub fn detect_mods_in_archive(
        &self,
        info: &ArchiveInfo,
        map: &PristineMap,
        opts: &ModOptions,
    ) -> ModReport {
        let mut out = self.compare_archive(info, map, opts);
        settle(&mut out);
        out
    }

    /// One archive's comparison, in whatever thread pool is already installed.
    fn compare_archive(
        &self,
        info: &ArchiveInfo,
        map: &PristineMap,
        opts: &ModOptions,
    ) -> ModReport {
        let archive = ContainerRef::new(info.repo, info.id, ContainerId::Archive);
        let accounted = map.accounts_for(info.repo);
        let mut out = ModReport::default();

        // The index containers hold no files, so they get a standing and nothing else. What their
        // bytes cannot say is which *entries* moved: a row inserted into a sorted entry segment
        // shifts every row after it, so a rewritten index would otherwise read as every file in the
        // archive having been retargeted. Where a file's bytes are is what decides, and that is the
        // data-file side below.
        for kind in [IndexKind::Index1, IndexKind::Index2] {
            let at = archive.with_file(ContainerId::Index(kind));
            let actual_len = info
                .has_index(kind)
                .then(|| {
                    std::fs::metadata(info.index_path(kind))
                        .ok()
                        .map(|m| m.len())
                })
                .flatten();
            // A form the tree does not have is skipped unless the map says it should be there, in
            // which case its absence is the finding.
            if actual_len.is_some() || map.coverage(at).is_some() {
                out.containers
                    .push(container_verdict(at, map, accounted, actual_len));
            }
        }

        let Some(locations) = self.locations_of(info) else {
            // Neither index form parsed, so nothing names the files this archive holds and none of
            // them can be judged. Reported rather than silently contributing no verdicts, which is
            // what would otherwise let a wrecked archive read as a clean one.
            out.totals.containers_unreadable += 1;
            out.containers.push(ContainerVerdict {
                container: archive,
                standing: ContainerStanding::Unknown,
                pristine_len: None,
                actual_len: None,
            });
            return out;
        };

        // Every data file the archive could have: the ones on disk, the ones the index sends entries
        // into, and the ones the map says should exist. A file the index names and the tree has lost
        // would otherwise take its entries out of the report entirely.
        let mut wanted: BTreeSet<u8> = info.dats.iter().copied().collect();
        wanted.extend(locations.iter().map(|located| located.dat));
        wanted.extend(map.containers().filter_map(|(at, _)| match at.file {
            ContainerId::Dat(dat) if at.repo == info.repo && at.archive == info.id => Some(dat),
            _ => None,
        }));
        let present: BTreeSet<u8> = info.dats.iter().copied().collect();

        let comparisons: Vec<ContainerComparison> = wanted
            .par_iter()
            .map(|dat| {
                if present.contains(dat) {
                    self.compare_dat(info, *dat, &locations, archive, map, accounted, opts)
                } else {
                    absent_dat(*dat, &locations, archive, map, opts)
                }
            })
            .collect();
        for comparison in comparisons {
            absorb(&mut out, comparison);
        }
        out
    }

    /// Every location the archive's primary index form names, ascending, or nothing when neither
    /// form parses.
    ///
    /// The primary form is the `.index` when it parsed, which is the rule `lookup` and the structural
    /// sweep both follow: its 64-bit key is what an answer is judged by, and both forms name the same
    /// places. Two consequences worth stating rather than discovering. A retarget applied to one form
    /// only is invisible here and is [`crate::integrity::Defect::FormsDisagree`]'s to report, since
    /// that check exists and compares the two form's locations directly. And two keys naming one
    /// offset, which is how a collision table spells a synonym, are two files sharing one entry and
    /// so two verdicts over one extent.
    fn locations_of(&self, info: &ArchiveInfo) -> Option<Vec<Located>> {
        let opts = SweepOptions::default();
        for kind in [IndexKind::Index1, IndexKind::Index2] {
            if !info.has_index(kind) {
                continue;
            }
            let Ok(bytes) = index::read_capped(&info.index_path(kind), &opts.index_limits) else {
                continue;
            };
            let facts = IndexFacts {
                container: ContainerRef::new(info.repo, info.id, ContainerId::Index(kind)),
                named: kind,
                dats: &info.dats,
            };
            let inspection = inspect_index(&bytes, &facts, &opts);
            if inspection.index.is_some() {
                return Some(inspection.locations);
            }
        }
        // `None` rather than an empty list, which is a different fact: an archive can legitimately
        // name nothing, and an archive whose every index form is unreadable names nothing *knowable*.
        None
    }

    /// One data file, opened directly rather than through the handle's cache so a comparison over a
    /// hundred gigabytes does not leave every container's handle behind.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one fact the comparison needs and none of them group into a \
                  type that would be used anywhere else"
    )]
    fn compare_dat(
        &self,
        info: &ArchiveInfo,
        dat: u8,
        locations: &[Located],
        archive: ContainerRef,
        map: &PristineMap,
        accounted: bool,
        opts: &ModOptions,
    ) -> ContainerComparison {
        let at = archive.with_file(ContainerId::Dat(dat));
        let named = locations_in(locations, dat);
        let coverage = map.coverage(at);

        // A container the map vouches for is answered from its length alone, so it is not even
        // opened: the whole point of the short circuit is that a pristine install costs nothing.
        // The length still has to come from the filesystem rather than from the map.
        let actual_len = std::fs::metadata(info.dat_path(dat)).ok().map(|m| m.len());
        if let (Some(coverage), Some(actual_len)) = (coverage, actual_len)
            && coverage.vouches_whole(actual_len)
        {
            return ContainerComparison {
                verdict: Some(ContainerVerdict {
                    container: at,
                    standing: ContainerStanding::Pristine,
                    pristine_len: Some(coverage.pristine_len()),
                    actual_len: Some(actual_len),
                }),
                totals: ModTotals {
                    containers: 1,
                    pristine: named.len() as u64,
                    ..ModTotals::default()
                },
                ..ContainerComparison::default()
            };
        }

        let container = match crate::dat::Dat::open(info.dat_path(dat)) {
            Ok(container) => container,
            Err(_) => {
                return ContainerComparison {
                    verdict: Some(ContainerVerdict {
                        container: at,
                        standing: ContainerStanding::Unknown,
                        pristine_len: coverage.map(crate::mods::Coverage::pristine_len),
                        actual_len,
                    }),
                    totals: ModTotals {
                        containers: 1,
                        containers_unreadable: 1,
                        unknown: named.len() as u64,
                        ..ModTotals::default()
                    },
                    ..ContainerComparison::default()
                };
            }
        };
        classify_entries(&container, named, coverage, accounted, at, opts)
    }
}

/// A data file the archive should have and does not: the map describes it, or its index sends
/// entries into it, and it is not on disk.
///
/// Every file it would have held is [`crate::mods::Standing::Broken`], since what it would deliver
/// cannot be read at all. That is deliberately not "would be replaced": a repair restores these
/// rather than reverting them, and warning about them would put files a user never touched in the
/// list of files a user is about to lose.
fn absent_dat(
    dat: u8,
    locations: &[Located],
    archive: ContainerRef,
    map: &PristineMap,
    opts: &ModOptions,
) -> ContainerComparison {
    let at = archive.with_file(ContainerId::Dat(dat));
    let named = locations_in(locations, dat);
    let mut out = ContainerComparison {
        verdict: Some(ContainerVerdict {
            container: at,
            standing: ContainerStanding::Missing,
            pristine_len: map.coverage(at).map(Coverage::pristine_len),
            actual_len: None,
        }),
        totals: ModTotals {
            containers: 1,
            containers_unreadable: 1,
            ..ModTotals::default()
        },
        ..ContainerComparison::default()
    };
    file_verdicts(&mut out, named, at, Standing::Broken, opts);
    out
}

/// How a container with no entries of its own stands, from the map and its length.
fn container_verdict(
    at: ContainerRef,
    map: &PristineMap,
    accounted: bool,
    actual_len: Option<u64>,
) -> ContainerVerdict {
    let Some(coverage) = map.coverage(at) else {
        return ContainerVerdict {
            container: at,
            standing: if accounted {
                ContainerStanding::Added
            } else {
                ContainerStanding::Unknown
            },
            pristine_len: None,
            actual_len,
        };
    };
    let Some(actual_len) = actual_len else {
        return ContainerVerdict {
            container: at,
            standing: ContainerStanding::Unknown,
            pristine_len: Some(coverage.pristine_len()),
            actual_len: None,
        };
    };
    let standing = if actual_len > coverage.pristine_len() {
        ContainerStanding::Grown
    } else if actual_len < coverage.pristine_len() {
        ContainerStanding::Truncated
    } else if coverage.dirty().is_empty() {
        ContainerStanding::Pristine
    } else {
        ContainerStanding::Rewritten
    };
    ContainerVerdict {
        container: at,
        standing,
        pristine_len: Some(coverage.pristine_len()),
        actual_len: Some(actual_len),
    }
}

/// The stretch of `locations` naming one data file. Sorted by `(dat, offset, key)`, so this is two
/// boundaries rather than a filter over millions of entries.
fn locations_in(locations: &[Located], dat: u8) -> &[Located] {
    let start = locations.partition_point(|located| located.dat < dat);
    let end = locations.partition_point(|located| located.dat <= dat);
    locations.get(start..end).unwrap_or_default()
}

/// Fold one container's comparison into an archive's report.
fn absorb(out: &mut ModReport, comparison: ContainerComparison) {
    out.files.extend(comparison.files);
    out.containers.extend(comparison.verdict);
    out.totals.merge(&comparison.totals);
    if comparison.truncated
        && let Some(verdict) = comparison.verdict
    {
        out.truncated.push(verdict.container);
    }
}

/// Fold one archive's report into the install's.
fn merge(out: &mut ModReport, report: ModReport) {
    out.files.extend(report.files);
    out.containers.extend(report.containers);
    out.totals.merge(&report.totals);
    out.truncated.extend(report.truncated);
}

/// Put a report into the order its documentation promises, so two runs at any thread count compare
/// equal.
fn settle(out: &mut ModReport) {
    out.files
        .sort_unstable_by_key(|file| (file.container, file.offset, file.key));
    out.containers.sort_unstable_by_key(|v| v.container);
    out.truncated.sort_unstable();
    out.truncated.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveId;
    use crate::dat::builder::EntrySpec;
    use crate::game::Repo;
    use crate::integrity::fixture::ArchiveFixture;
    use crate::mods::{Confidence, MapBuilder, Standing};
    use std::path::{Path, PathBuf};

    /// Two clean archives in two repositories, the same tree the structural sweep's tests use.
    fn archives() -> Vec<ArchiveFixture> {
        let mut other = ArchiveFixture::clean(Repo::Ex(1), ArchiveId::new(0x02, 1, 1));
        other.file(
            0,
            "bg/ex1/01_roc_r2/twn/r2t1/level/planmap.lgb",
            EntrySpec::standard(vec![b"PLANMAP".repeat(30)]),
        );
        vec![
            ArchiveFixture::clean(Repo::Base, ArchiveId::new(0x0a, 0, 0)),
            other,
        ]
    }

    fn write_tree(archives: &[ArchiveFixture]) -> (tempfile::TempDir, GameData) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("ffxivgame.ver"), "2026.07.16.0001.0000").unwrap();
        for fixture in archives {
            let (repo, _) = fixture.id();
            fixture
                .write_to(&tmp.path().join("sqpack").join(repo.dir_name()))
                .unwrap();
        }
        let game = GameData::open(tmp.path()).unwrap();
        (tmp, game)
    }

    /// A map describing exactly the tree at `root`: every container at the length it currently has,
    /// nothing dirty. This is what a verification of an untouched install lowers to, and building it
    /// from the tree is the only honest way to get one without a real patch chain.
    fn map_of(root: &Path, repos: &[Repo]) -> PristineMap {
        let mut b = PristineMap::builder();
        for repo in repos {
            b.accounts_for(*repo);
        }
        for path in containers(root) {
            let rel = path.strip_prefix(root).unwrap();
            let at = ContainerRef::from_relative_path(rel)
                .unwrap_or_else(|| panic!("not a container: {}", rel.display()));
            b.container(at, std::fs::metadata(&path).unwrap().len());
        }
        b.build()
    }

    /// Every SqPack container under a game tree.
    fn containers(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.join("sqpack")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn a_pristine_install_is_all_pristine_and_no_entry_is_read() {
        // The gate. It is not merely that nothing is reported: a container the map vouches for is
        // never opened, so on a pristine tree there is no check running that could report anything.
        let fixtures = archives();
        let (tmp, game) = write_tree(&fixtures);
        let map = map_of(tmp.path(), &[Repo::Base, Repo::Ex(1)]);

        let report = game.detect_mods(&map, &ModOptions::default());
        assert!(report.is_pristine(), "{:#?}", report.files);
        assert!(report.is_exhaustive());
        assert_eq!(report.would_be_replaced(), 0);
        assert!(report.files.is_empty());
        assert_eq!(report.totals.entry_headers_read, 0);
        assert!(report.totals.pristine > 0);
        assert!(
            report
                .containers
                .iter()
                .all(|v| v.standing == ContainerStanding::Pristine),
            "{:#?}",
            report.containers
        );
    }

    #[test]
    fn a_file_moved_to_the_end_of_its_archive_is_the_only_one_reported() {
        // The shape every appending mod tool leaves: the file's bytes go past where the patch chain
        // left the container, the index row follows them, and what it used to hold stays put with
        // nothing naming it. The whole answer comes from a length, so it does not depend on how
        // finely anything measured the bytes.
        let fixtures = archives();
        let (tmp, game) = write_tree(&fixtures);
        let map = map_of(tmp.path(), &[Repo::Base, Repo::Ex(1)]);

        let mut modded = archives();
        modded[0].retarget(
            0,
            "exd/item.exh",
            EntrySpec::standard(vec![b"MODDED".repeat(900)]),
        );
        let (repo, id) = modded[0].id();
        modded[0]
            .write_to(&tmp.path().join("sqpack").join(repo.dir_name()))
            .unwrap();
        let game = GameData::open(game.game_dir()).unwrap();

        let report = game.detect_mods(&map, &ModOptions::default());
        assert!(!report.is_pristine());
        assert!(report.is_exhaustive());
        assert_eq!(report.would_be_replaced(), 1);
        let file = report.replaced().next().unwrap();
        assert_eq!(file.standing, Standing::Foreign);
        // Exact even though the map has no dirty range at all: a length said so.
        assert_eq!(file.confidence, Confidence::Exact);
        assert_eq!(file.key, crate::hash::hash_path("exd/item.exh").key());
        assert_eq!(file.container.archive, id);
        assert_eq!(report.totals.shared, 0);

        // The archive that holds it grew; the one nothing touched is untouched, and its containers
        // are still answered without a read.
        let grown: Vec<_> = report
            .containers
            .iter()
            .filter(|v| v.standing != ContainerStanding::Pristine)
            .collect();
        assert_eq!(grown.len(), 1);
        assert_eq!(grown[0].standing, ContainerStanding::Grown);
        assert_eq!(grown[0].container.archive, id);
    }

    #[test]
    fn a_map_that_covers_one_repository_says_nothing_about_the_others() {
        // The guard that keeps a base-game index from reporting every expansion archive as a mod
        // tool's work. Getting this wrong is the worst mistake available here.
        let fixtures = archives();
        let (tmp, game) = write_tree(&fixtures);
        let mut b = MapBuilder::default();
        b.accounts_for(Repo::Base);
        for path in containers(tmp.path()) {
            let rel = path.strip_prefix(tmp.path()).unwrap();
            let at = ContainerRef::from_relative_path(rel).unwrap();
            if at.repo == Repo::Base {
                b.container(at, std::fs::metadata(&path).unwrap().len());
            }
        }
        let report = game.detect_mods(&b.build(), &ModOptions::default());

        assert!(report.is_pristine());
        assert_eq!(report.would_be_replaced(), 0);
        // But it is not exhaustive, and every unjudged file is in the repository the map skipped.
        assert!(!report.is_exhaustive());
        assert!(report.totals.unknown > 0);
        assert_eq!(report.totals.foreign, 0);
        assert!(
            report
                .of_standing(Standing::Unknown)
                .all(|f| f.container.repo == Repo::Ex(1))
        );
    }

    #[test]
    fn the_same_tree_reports_the_same_thing_in_the_same_order_every_time() {
        // The map covers neither repository, so every file in the tree is carried rather than
        // counted. A pristine tree would leave the list empty and make the ordering assertion below
        // pass whatever the sort did.
        let fixtures = archives();
        let (_tmp, game) = write_tree(&fixtures);
        let map = PristineMap::builder().build();
        let one = game.detect_mods(&map, &ModOptions::default());
        assert!(one.files.len() > 4, "the list has to have content to order");
        assert!(
            one.files
                .iter()
                .map(|f| f.container)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                > 1,
            "and has to span containers, or the ordering is within one"
        );
        assert_eq!(one, game.detect_mods(&map, &ModOptions::default()));
        // Ascending by container, then by where in it the file sits, so a caller reads the list
        // archive by archive and in the order a repair would walk it.
        assert!(
            one.files
                .windows(2)
                .all(|p| (p[0].container, p[0].offset, p[0].key)
                    <= (p[1].container, p[1].offset, p[1].key))
        );
        assert!(
            one.containers
                .windows(2)
                .all(|p| p[0].container <= p[1].container)
        );
    }

    #[test]
    fn one_archive_on_its_own_answers_what_the_whole_tree_pass_said_about_it() {
        let fixtures = archives();
        let (tmp, game) = write_tree(&fixtures);
        let map = map_of(tmp.path(), &[Repo::Base, Repo::Ex(1)]);
        let (repo, id) = fixtures[0].id();
        let info = game.archive(repo, id).unwrap();
        let alone = game.detect_mods_in_archive(info, &map, &ModOptions::default());
        assert!(alone.is_pristine());
        assert_eq!(alone.totals.containers, info.dats.len() as u32);

        let whole = game.detect_mods(&map, &ModOptions::default());
        let mine: Vec<_> = whole
            .containers
            .iter()
            .filter(|v| v.container.archive == id && v.container.repo == repo)
            .copied()
            .collect();
        assert_eq!(alone.containers, mine);
    }

    #[test]
    fn an_archive_whose_indexes_will_not_parse_is_not_a_clean_one() {
        // Nothing names the files it holds, so none of them can be judged. Contributing no verdicts
        // at all would let a wrecked archive disappear into a report that then calls itself clean
        // and exhaustive.
        let fixtures = archives();
        let (tmp, game) = write_tree(&fixtures);
        let map = map_of(tmp.path(), &[Repo::Base, Repo::Ex(1)]);
        let (repo, id) = fixtures[0].id();
        for kind in [IndexKind::Index1, IndexKind::Index2] {
            let path = tmp
                .path()
                .join("sqpack")
                .join(repo.dir_name())
                .join(id.index_file_name(kind));
            let bytes = std::fs::read(&path).unwrap();
            std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        }
        let game = GameData::open(game.game_dir()).unwrap();
        let report = game.detect_mods(&map, &ModOptions::default());

        assert!(!report.is_exhaustive());
        assert_eq!(report.totals.containers_unreadable, 1);
        assert!(report.containers.iter().any(|v| v.container.archive == id
            && v.container.file == ContainerId::Archive
            && v.standing == ContainerStanding::Unknown));
        // The other archive is untouched and still says so.
        assert_eq!(report.would_be_replaced(), 0);
    }

    #[test]
    fn a_data_file_the_map_has_and_the_tree_does_not_is_reported_rather_than_dropped() {
        // Deleting a container takes its entries out of the on-disk walk entirely, so the files it
        // held would simply vanish from the report: an install missing an archive would read exactly
        // like one that is whole.
        let fixtures = archives();
        let (tmp, game) = write_tree(&fixtures);
        let map = map_of(tmp.path(), &[Repo::Base, Repo::Ex(1)]);
        let (repo, id) = fixtures[0].id();
        std::fs::remove_file(
            tmp.path()
                .join("sqpack")
                .join(repo.dir_name())
                .join(id.dat_file_name(1)),
        )
        .unwrap();
        let game = GameData::open(game.game_dir()).unwrap();
        let report = game.detect_mods(&map, &ModOptions::default());

        let missing: Vec<_> = report
            .altered_containers()
            .filter(|v| v.standing == ContainerStanding::Missing)
            .collect();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].container.file, ContainerId::Dat(1));
        assert!(missing[0].pristine_len.is_some());
        assert!(missing[0].actual_len.is_none());

        // Its files are broken, not "would be replaced": a repair restores them rather than
        // reverting them, and warning about them would name files the user never touched.
        assert!(report.totals.broken > 0);
        assert_eq!(report.would_be_replaced(), 0);
        assert!(!report.is_pristine());
        assert!(!report.is_exhaustive());
        assert!(
            report
                .of_standing(Standing::Broken)
                .all(|f| f.container.file == ContainerId::Dat(1))
        );
    }

    #[test]
    fn a_data_file_the_pristine_install_did_not_have_is_reported_whole() {
        // A mod tool that adds a data file rather than growing one. Every entry the index sends into
        // it is foreign, and the container itself says it was added.
        let mut fixtures = archives();
        fixtures[0].file(
            1,
            "exd/added.exl",
            EntrySpec::standard(vec![b"ADDED".to_vec()]),
        );
        let (tmp, game) = write_tree(&fixtures);
        let mut b = MapBuilder::default();
        b.accounts_for(Repo::Base);
        for path in containers(tmp.path()) {
            let rel = path.strip_prefix(tmp.path()).unwrap();
            let at = ContainerRef::from_relative_path(rel).unwrap();
            // The map knows every container but the second data file of the first archive.
            if at.repo == Repo::Base && at.file != ContainerId::Dat(1) {
                b.container(at, std::fs::metadata(&path).unwrap().len());
            }
        }
        let report = game.detect_mods(&b.build(), &ModOptions::default());

        assert!(report.would_be_replaced() > 0);
        assert!(
            report
                .replaced()
                .all(|f| f.standing == Standing::Foreign
                    && f.container.file == ContainerId::Dat(1))
        );
        // Only that container was read, and only for the extents: every other data file of the
        // install is answered from its length, which is what keeps the pass cheap.
        assert_eq!(report.totals.entry_headers_read, report.would_be_replaced());
        assert!(report.replaced().all(|f| f.len > 0));
        assert!(
            report
                .containers
                .iter()
                .any(|v| v.standing == ContainerStanding::Added)
        );
    }
}
