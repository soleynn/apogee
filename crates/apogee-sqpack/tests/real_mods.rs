//! Mod detection over a real install, which is the only place its false-positive rate can be
//! measured.
//!
//! Every rule the comparison applies was written from a measurement over a full retail install, and
//! the rule that matters most is negative: on a tree nothing has touched, no file is reported. A
//! synthetic archive cannot say whether that holds, because a synthetic archive carries the shapes
//! somebody thought to build. A real one carries 1.9 M entries including the ones nobody would think
//! of: the placeholders whose size words are a previous occupant's leftovers, the volume textures
//! that declare more than they store, the entries that occupy nothing under a large allocation, the
//! data files with no `SqPack` magic.
//!
//! The maps here are built from the tree itself rather than from a patch chain, deliberately. What is
//! being measured is not whether a chain agrees with an install, which the agreement suite covers
//! hermetically; it is whether the comparison attributes bytes to files correctly over every shape a
//! real archive contains. So each case states a byte range and the files it must or must not
//! implicate, and the tree supplies the entries.
//!
//! Gated on `$APOGEE_SQPACK_REAL_INSTALL` and `#[ignore]` by default. The walk is two million
//! positioned reads, the same cost as the structural sweep's entry pass.

use std::error::Error;
use std::path::Path;

use apogee_sqpack::integrity::{ContainerId, ContainerRef};
use apogee_sqpack::mods::{
    Confidence, ContainerStanding, MapBuilder, ModOptions, ModReport, PristineMap, Standing,
};
use apogee_sqpack::{GameData, IndexKind};

type R<T> = Result<T, Box<dyn Error>>;

fn install() -> R<GameData> {
    let root = std::env::var("APOGEE_SQPACK_REAL_INSTALL")?;
    Ok(GameData::open(Path::new(&root))?)
}

/// Every container of the install, with the length it has on disk.
fn containers(game: &GameData) -> R<Vec<(ContainerRef, u64)>> {
    let mut out = Vec::new();
    for info in game.archives() {
        for kind in [IndexKind::Index1, IndexKind::Index2] {
            if info.has_index(kind) {
                let path = info.index_path(kind);
                let at = ContainerRef::new(info.repo, info.id, ContainerId::Index(kind));
                out.push((at, std::fs::metadata(path)?.len()));
            }
        }
        for dat in &info.dats {
            let at = ContainerRef::new(info.repo, info.id, ContainerId::Dat(*dat));
            out.push((at, std::fs::metadata(info.dat_path(*dat))?.len()));
        }
    }
    Ok(out)
}

/// A builder describing every container at the length it has, accounting for every repository, with
/// `shape` free to say what disagrees.
fn map_of(game: &GameData, shape: impl Fn(&mut MapBuilder, ContainerRef, u64)) -> R<PristineMap> {
    let mut b = PristineMap::builder();
    for info in game.repos() {
        b.accounts_for(info.repo);
    }
    for (at, len) in containers(game)? {
        shape(&mut b, at, len);
    }
    Ok(b.build())
}

/// The data files of the install, which is where files live.
fn data_files(game: &GameData) -> R<Vec<(ContainerRef, u64)>> {
    Ok(containers(game)?
        .into_iter()
        .filter(|(at, _)| matches!(at.file, ContainerId::Dat(_)))
        .collect())
}

fn run(game: &GameData, map: &PristineMap) -> ModReport {
    game.detect_mods(map, &ModOptions::default())
}

#[test]
#[ignore = "needs a real install at $APOGEE_SQPACK_REAL_INSTALL"]
fn an_untouched_install_reports_nothing_and_reads_nothing() -> R<()> {
    let game = install()?;
    let map = map_of(&game, |b, at, len| {
        b.container(at, len);
    })?;
    let report = run(&game, &map);

    assert!(report.is_pristine(), "{:#?}", &report.files[..]);
    assert!(report.is_exhaustive());
    assert_eq!(report.would_be_replaced(), 0);
    assert!(report.files.is_empty());
    // The whole install is answered from lengths, so not one of the two million entry headers is
    // read. This is the property the pre-repair prompt's cost rests on.
    assert_eq!(report.totals.entry_headers_read, 0);
    assert!(report.totals.pristine > 1_000_000, "{:?}", report.totals);
    assert!(
        report
            .containers
            .iter()
            .all(|v| v.standing == ContainerStanding::Pristine)
    );
    Ok(())
}

#[test]
#[ignore = "needs a real install at $APOGEE_SQPACK_REAL_INSTALL"]
fn a_container_header_that_differs_implicates_no_file_at_all() -> R<()> {
    // The check with the most to prove. A mod tool rewriting an archive rewrites its headers, and a
    // container's first `0x800` bytes belong to no file, so the run covering them must implicate
    // nothing. Every data file of the install is walked entry by entry to say so: this is the pass
    // the short circuit above skips, over every entry shape a real archive holds.
    let game = install()?;
    let map = map_of(&game, |b, at, len| {
        b.container(at, len).dirty(at, 0, 0x800);
    })?;
    let report = run(&game, &map);

    // Not one file, out of the whole install.
    assert_eq!(report.would_be_replaced(), 0, "{:#?}", &report.files[..]);
    assert!(report.files.is_empty(), "{:#?}", &report.files[..]);
    assert_eq!(report.totals.modified, 0);
    assert_eq!(report.totals.foreign, 0);
    assert_eq!(report.totals.broken, 0);
    assert!(report.is_exhaustive());
    // And the walk really ran: one header read per entry the indexes named.
    assert_eq!(report.totals.entry_headers_read, report.totals.pristine);
    assert!(report.totals.entry_headers_read > 1_000_000);
    // The containers themselves *are* altered, and the report says so. The install is not pristine,
    // which is the difference between "nothing here is a file a repair would revert" and "nothing
    // here changed": something rewrote every container and no file's content moved with it.
    assert!(!report.is_pristine());
    assert_eq!(report.altered_containers().count(), report.containers.len());
    assert!(
        report
            .containers
            .iter()
            .filter(|v| matches!(v.container.file, ContainerId::Dat(_)))
            .all(|v| v.standing == ContainerStanding::Rewritten)
    );
    Ok(())
}

#[test]
#[ignore = "needs a real install at $APOGEE_SQPACK_REAL_INSTALL"]
fn bytes_past_the_length_a_container_should_have_implicate_only_the_files_in_them() -> R<()> {
    // The appending signature, measured on real entries. Every data file is declared one unit shorter
    // than it is, so whatever sits in that last unit is foreign and nothing else is. On a real
    // install the answer is a handful of files out of two million, and each is exact, because a
    // length says so rather than a run of bytes.
    let game = install()?;
    let unit = u64::from(apogee_sqpack::DATA_UNIT);
    let map = map_of(&game, |b, at, len| {
        let shortened = match at.file {
            ContainerId::Dat(_) => len.saturating_sub(unit),
            _ => len,
        };
        b.container(at, shortened);
    })?;
    let report = run(&game, &map);

    assert!(!report.is_pristine());
    assert!(report.is_exhaustive());
    assert_eq!(report.totals.modified, 0);
    assert_eq!(report.totals.broken, 0);
    assert!(report.totals.foreign > 0);
    // A verdict from a length is never shared, however coarse anything else was.
    assert!(
        report
            .replaced()
            .all(|f| f.standing == Standing::Foreign && f.confidence == Confidence::Exact)
    );
    // At most one entry of each data file can end in its last unit, so the count is bounded by the
    // container count rather than by the entry count.
    let dats = data_files(&game)?.len() as u64;
    assert!(
        report.totals.foreign <= dats,
        "{} foreign across {dats} data files",
        report.totals.foreign
    );
    assert!(
        report
            .containers
            .iter()
            .filter(|v| matches!(v.container.file, ContainerId::Dat(_)))
            .all(|v| v.standing == ContainerStanding::Grown)
    );
    Ok(())
}

#[test]
#[ignore = "needs a real install at $APOGEE_SQPACK_REAL_INSTALL"]
fn a_map_that_covers_nothing_judges_nothing_rather_than_condemning_everything() -> R<()> {
    // The guard, over a real install: an empty map with no repository accounted for must leave every
    // one of two million files unknown, not foreign. Getting this backwards would tell a user with a
    // pristine install that every file in it was put there by a mod tool.
    let game = install()?;
    let report = run(&game, &PristineMap::builder().build());

    assert!(report.is_pristine());
    assert!(!report.is_exhaustive());
    assert_eq!(report.would_be_replaced(), 0);
    assert_eq!(report.totals.foreign, 0);
    assert!(report.totals.unknown > 1_000_000);
    assert_eq!(report.totals.entry_headers_read, 0);
    Ok(())
}
