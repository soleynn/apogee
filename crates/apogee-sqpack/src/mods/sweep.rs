//! Driving the comparison over a whole install: the same shape [`crate::integrity`]'s sweep has, for
//! the same reasons. One archive is the unit of work and the archives run in parallel, because a
//! single data file of a real install can be an eighth of it.
//!
//! Where this differs from the structural sweep is what it costs. That one reads every entry header
//! of the install; this one reads none at all in a container the map vouches for, so its cost tracks
//! how much of the install disagrees rather than how large the install is.

use rayon::prelude::*;

use crate::game::{ArchiveInfo, GameData};
use crate::index::{self, IndexKind};
use crate::integrity::{
    ContainerId, ContainerRef, IndexFacts, Located, SweepOptions, inspect_index,
};
use crate::mods::classify::{ContainerComparison, classify_entries};
use crate::mods::map::PristineMap;
use crate::mods::verdict::{ContainerStanding, ContainerVerdict};
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
            if !info.has_index(kind) {
                continue;
            }
            let at = archive.with_file(ContainerId::Index(kind));
            let actual_len = std::fs::metadata(info.index_path(kind))
                .ok()
                .map(|meta| meta.len());
            out.containers
                .push(container_verdict(at, map, accounted, actual_len));
        }

        let locations = self.locations_of(info);
        let comparisons: Vec<ContainerComparison> = info
            .dats
            .par_iter()
            .map(|dat| self.compare_dat(info, *dat, &locations, archive, map, accounted, opts))
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
    fn locations_of(&self, info: &ArchiveInfo) -> Vec<Located> {
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
                return inspection.locations;
            }
        }
        Vec::new()
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
    fn the_same_tree_reports_the_same_thing_at_any_thread_count() {
        let fixtures = archives();
        let (tmp, game) = write_tree(&fixtures);
        let map = map_of(tmp.path(), &[Repo::Base]);
        let one = game.detect_mods(&map, &ModOptions::default());
        assert_eq!(one, game.detect_mods(&map, &ModOptions::default()));
        // Ascending by container, so a caller reads the list archive by archive.
        assert!(
            one.files
                .windows(2)
                .all(|pair| pair[0].container <= pair[1].container)
        );

        // One archive on its own answers exactly what the whole-tree pass said about it.
        let (repo, id) = fixtures[0].id();
        let info = game.archive(repo, id).unwrap();
        let alone = game.detect_mods_in_archive(info, &map, &ModOptions::default());
        assert!(alone.is_pristine());
        assert_eq!(alone.totals.containers, info.dats.len() as u32);
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
        // Not one byte of it was read to say so.
        assert_eq!(report.totals.entry_headers_read, 0);
        assert!(
            report
                .containers
                .iter()
                .any(|v| v.standing == ContainerStanding::Added)
        );
    }
}
