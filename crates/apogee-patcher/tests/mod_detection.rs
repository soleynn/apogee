//! What a block index and a verification of it can say about which files somebody modified.
//!
//! This is the half of the two crates' agreement that needs both of them at once, and so needs the
//! layer that composes them. `apogee-zipatch` owns the chain and the verification, `apogee-sqpack`
//! owns the archive and the comparison, and neither can reach the other: the byte-range map between
//! them is built here. The format half, that a patched tree reads back as an archive at all, is
//! asserted in `apogee-zipatch`'s own suite.
//!
//! Three things, in the order they depend on each other:
//!
//! 1. the chain's index, verified against the tree it produced, lowers to a map that finds the
//!    install entirely pristine, having read no entry header at all;
//! 2. the same map over a tree a mod tool has been at names exactly the file it moved;
//! 3. an index built for another version is refused rather than believed.
//!
//! The archive bytes come from `apogee-sqpack`'s own builders, through its `test-fixtures` feature,
//! so the layout has one owner and this file cannot drift from the reader it is checking.

use std::error::Error;
use std::path::Path;

use apogee_patcher::mods::{MapError, describe_containers};
use apogee_sqpack::fixtures::{ArchiveFixture, EntrySpec};
use apogee_sqpack::integrity::ContainerRef;
use apogee_sqpack::mods::{ModOptions, PristineMap, Standing};
use apogee_sqpack::{ArchiveId, GameData, IndexKind, MODEL_LOD_COUNT, Repo};
use apogee_zipatch::fixtures::{PatchBuilder, block_deflate, block_stored};
use apogee_zipatch::{Index, Platform, VerifyOptions, VerifyReport, build_index, fixtures};

type R<T> = Result<T, Box<dyn Error>>;

/// The platform word a target-info chunk carries for win32.
const WIN32: u16 = 0;

/// What a real block holds at most once decompressed, so a file is written as a run of them rather
/// than as one impossible block.
const BLOCK_BYTES: usize = 16_000;

/// The tree both halves of this test are about: one archive per category, because a lookup routes a
/// path to an archive by its first segment, so a file only resolves from the archive its own
/// category names. Between them the three carry every content type, several data files, slack
/// inside a slot and the wiped regions a patcher stamps.
fn archives() -> Vec<ArchiveFixture> {
    let mut common = ArchiveFixture::new(Repo::Base, ArchiveId::new(0x00, 0, 0), 1);
    common
        .file(
            0,
            "common/font/font1.tex",
            EntrySpec::texture_blocks(
                vec![0xAB; 80],
                vec![vec![vec![1u8; 4096], vec![2u8; 4096]], vec![vec![3u8; 256]]],
            ),
        )
        .gap(0, 3)
        // A volume texture declares padding between mip surfaces that the archive does not store.
        .file(
            0,
            "common/font/font2.tex",
            EntrySpec::texture_declaring(vec![0xCD; 80], vec![vec![3u8; 512]], 4096),
        );

    let mut exd = ArchiveFixture::new(Repo::Base, ArchiveId::new(0x0a, 0, 0), 2);
    exd.file(
        0,
        "exd/root.exl",
        EntrySpec::standard(vec![b"ROOT".to_vec()]),
    )
    .file(
        0,
        "exd/item.exh",
        EntrySpec::standard(vec![b"ITEM ".repeat(500), b"tail".to_vec()]),
    )
    .file(0, "exd/empty.exd", EntrySpec::standard(vec![]));
    exd.dat(1).slack(2);
    exd.file(
        1,
        "exd/deleted.exd",
        EntrySpec::empty_with_leftovers(83_952, 2, 57_472),
    );
    exd.dat(1).slack(0);
    exd.file(
        1,
        "exd/spanned.exd",
        EntrySpec::standard_stored(vec![b"SPANNED".repeat(200)]),
    )
    .gap_chain(1, &[2, 1, 5]);

    let mut chara = ArchiveFixture::new(Repo::Base, ArchiveId::new(0x04, 0, 0), 1);
    chara.file(
        0,
        "chara/monster/m0001/obj/body/b0001/model/m0001b0001.mdl",
        EntrySpec::model(model_sections()),
    );

    vec![common, exd, chara]
}

/// A model's eleven sections, two levels of detail carrying nothing at all.
fn model_sections() -> [Vec<u8>; 2 + 3 * MODEL_LOD_COUNT] {
    let mut sections: [Vec<u8>; 2 + 3 * MODEL_LOD_COUNT] = Default::default();
    sections[0] = b"stack".repeat(20);
    sections[1] = b"runtime".repeat(30);
    sections[2] = vec![7u8; 4096];
    sections[4] = vec![1u8; 300];
    sections
}

/// Every path the tree names, with what each should extract to. Derived from the fixtures rather
/// than written out, so the expectation is the bytes that went in.
fn expected(fixtures: &[ArchiveFixture]) -> Vec<(String, Vec<u8>)> {
    fixtures
        .iter()
        .flat_map(|fixture| fixture.built().files)
        .map(|file| (file.path, file.content))
        .collect()
}

/// A patch that lays every container of a tree down as a whole file, alternating stored and
/// compressed blocks so both codec paths carry real archive bytes rather than synthetic ones.
fn patch_for(fixtures: &[ArchiveFixture]) -> Vec<u8> {
    let mut b = PatchBuilder::new();
    b.fhdr(b"DIFF", 0).target_info(WIN32);
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for fixture in fixtures {
        let built = fixture.built();
        let (repo, id) = fixture.id();
        let dir = format!("sqpack/{}", repo.dir_name());
        files.push((
            format!("{dir}/{}", id.index_file_name(IndexKind::Index1)),
            built.index1,
        ));
        files.push((
            format!("{dir}/{}", id.index_file_name(IndexKind::Index2)),
            built.index2,
        ));
        for (n, dat) in built.dats.into_iter().enumerate() {
            files.push((format!("{dir}/{}", id.dat_file_name(n as u8)), dat.bytes));
        }
    }
    for (i, (path, bytes)) in files.iter().enumerate() {
        let mut blocks = Vec::new();
        for (j, chunk) in bytes.chunks(BLOCK_BYTES).enumerate() {
            // A container is written half one way and half the other: an archive's bytes are real
            // input for both block paths, and a stored-only patch would exercise neither the inflate
            // side nor the size checks around it.
            blocks.extend(if (i + j).is_multiple_of(2) {
                block_stored(chunk)
            } else {
                block_deflate(chunk)
            });
        }
        b.file_op(b'A', 0, bytes.len() as i64, path, &blocks);
    }
    b.eof();
    b.bytes()
}

/// Apply `patches` into a fresh tree and open it.
fn tree(patches: &[Vec<u8>]) -> R<(tempfile::TempDir, GameData)> {
    let tmp = tempfile::tempdir()?;
    fixtures::apply_chain(tmp.path(), patches)?;
    std::fs::write(tmp.path().join("ffxivgame.ver"), VERSION)?;
    let game = GameData::open(tmp.path())?;
    Ok((tmp, game))
}

/// The version the tree and every index in this file are at.
const VERSION: &str = "2026.07.16.0001.0000";

/// Build an index over a chain, labelled with the version the tree is at.
fn index_for(patches: &[Vec<u8>]) -> R<Index> {
    let inputs: Vec<(String, std::io::Cursor<Vec<u8>>)> = patches
        .iter()
        .enumerate()
        .map(|(i, p)| (format!("p{i}.patch"), std::io::Cursor::new(p.clone())))
        .collect();
    Ok(build_index(inputs, Platform::Win32, VERSION)?)
}

/// The map a chain and a verification of the tree it produced lower to.
fn map_from(index: &Index, root: &Path) -> R<(VerifyReport, PristineMap)> {
    let report = index.verify(root, &VerifyOptions::default())?;
    let mut builder = PristineMap::builder();
    describe_containers(index, &report, VERSION, &[Repo::Base], &mut builder)?;
    Ok((report, builder.build()))
}

#[test]
fn the_chain_that_built_a_tree_finds_it_entirely_pristine() -> R<()> {
    let fixtures = archives();
    let patches = vec![patch_for(&fixtures)];
    let (tmp, game) = tree(&patches)?;
    let index = index_for(&patches)?;

    let (verify, map) = map_from(&index, tmp.path())?;
    assert!(verify.is_clean(), "{verify:#?}");
    // The map has to actually describe every container, or a pristine result would be green for the
    // wrong reason: an empty map finds nothing wrong with anything.
    let containers: usize = fixtures.iter().map(|f| 2 + f.built().dats.len()).sum();
    assert_eq!(map.containers().len(), containers);
    for (at, coverage) in map.containers() {
        let on_disk = std::fs::metadata(tmp.path().join(at.relative_path()))?.len();
        assert_eq!(coverage.pristine_len(), on_disk, "{at:?}");
        assert!(coverage.dirty().is_empty(), "{at:?}");
    }

    let mods = game.detect_mods(&map, &ModOptions::default());
    assert!(mods.is_pristine(), "{:#?}", mods.files);
    assert!(mods.is_exhaustive());
    assert_eq!(mods.would_be_replaced(), 0);
    assert_eq!(mods.totals.pristine as usize, expected(&fixtures).len());
    // Not one entry header was read to say so.
    assert_eq!(mods.totals.entry_headers_read, 0);
    Ok(())
}

#[test]
fn a_tree_a_mod_tool_has_been_at_names_the_file_it_moved() -> R<()> {
    let fixtures = archives();
    let patches = vec![patch_for(&fixtures)];
    let (tmp, game) = tree(&patches)?;
    let index = index_for(&patches)?;
    let (_, map) = map_from(&index, tmp.path())?;

    // Append the modded bytes past where the chain left the container and repoint the row at them,
    // which is what every mod tool does, then write the result over the tree.
    let mut modded = archives();
    modded[1].retarget(
        0,
        "exd/item.exh",
        EntrySpec::standard(vec![b"MODDED BY A TOOL ".repeat(600)]),
    );
    modded[1].write_to(&tmp.path().join("sqpack/ffxiv"))?;
    let game = GameData::open(game.game_dir())?;

    // The map is the one built from the untouched tree: a caller does not re-derive it after the
    // damage, which is the whole point of it being a record of what the chain wrote.
    let mods = game.detect_mods(&map, &ModOptions::default());
    assert!(!mods.is_pristine());
    assert!(mods.is_exhaustive());
    assert_eq!(mods.would_be_replaced(), 1, "{:#?}", mods.files);
    let file = mods.replaced().next().unwrap();
    assert_eq!(file.standing, Standing::Foreign);
    assert_eq!(file.key, apogee_sqpack::hash_path("exd/item.exh").key());

    // The file it names is the one that moved, and the bytes it now delivers are the modded ones.
    let bytes = game.read("exd/item.exh")?.unwrap();
    assert!(bytes.starts_with(b"MODDED BY A TOOL "));
    let found = game.lookup("exd/item.exh")?.unwrap();
    assert_eq!(
        ContainerRef::from_relative_path(
            found
                .dat_path
                .strip_prefix(tmp.path())
                .unwrap_or(Path::new(""))
        ),
        Some(file.container)
    );

    // Every other file still reads back exactly as the patch wrote it: a mod tool that appends
    // leaves the rest of the archive alone, and a detector that said otherwise would be warning
    // about files a repair has no reason to touch.
    for (path, content) in expected(&fixtures) {
        if path == "exd/item.exh" {
            continue;
        }
        assert_eq!(game.read(&path)?.as_ref(), Some(&content), "{path}");
    }

    // What the block index says about the same tree, independently. The container grew, and *that*
    // is the signal the verdict above rested on: the appended bytes are past everything the chain
    // wrote, so no part covers them and none is reported broken over them.
    let verify = index.verify(tmp.path(), &VerifyOptions::default())?;
    assert!(!verify.is_clean());
    assert_eq!(verify.size_mismatches.len(), 1);
    let grew = &verify.size_mismatches[0];
    assert!(grew.actual > grew.expected);
    assert!(grew.path.ends_with("0a0000.win32.dat0"));
    assert!(
        verify
            .broken
            .iter()
            .all(|part| part.target_off < grew.expected),
        "nothing past the pristine end is reported as a broken range: {:#?}",
        verify.broken
    );

    // And the same thing again through the flow a launcher actually runs: verify the tree in front
    // of you, build the map from that, then ask what a repair would revert. The appended file is
    // still found, and still from a length, because the length the map carries is the chain's.
    let mut builder = PristineMap::builder();
    describe_containers(&index, &verify, VERSION, &[Repo::Base], &mut builder)?;
    let live = game.detect_mods(&builder.build(), &ModOptions::default());
    assert!(live.replaced().any(|f| f.standing == Standing::Foreign
        && f.key == apogee_sqpack::hash_path("exd/item.exh").key()));

    // It is noisier, and the reason is worth pinning rather than hiding. Rewriting a container
    // rewrites its header digests too, and every entry sharing a dirty run with them is reported
    // alongside. Here that is the whole container, because these fixtures are one block each; over
    // a real chain a write is 9 KB at the median against a mean entry of 61 KB, so the run that
    // covers a header covers about one entry rather than an archive's worth.
    for file in live.replaced() {
        assert!(
            file.container.repo == Repo::Base && file.container.archive.category == 0x0a,
            "only the archive the tool touched is implicated: {file}"
        );
    }
    Ok(())
}

#[test]
fn an_index_built_for_another_version_is_refused_rather_than_believed() -> R<()> {
    // The worst answer this comparison can give is not "I do not know", it is a confident list of
    // files the user never touched. An index one patch behind describes the lengths the tree had
    // before that patch, so every container the patch grew reads as one somebody appended to. There
    // is nothing downstream that can tell a stale map from a modded install, so it is refused here.
    let fixtures = archives();
    let patches = vec![patch_for(&fixtures)];
    let (tmp, game) = tree(&patches)?;
    let index = index_for(&patches)?;
    let report = index.verify(tmp.path(), &VerifyOptions::default())?;

    let mut builder = PristineMap::builder();
    let refused = describe_containers(
        &index,
        &report,
        "2026.07.03.0000.0000",
        &[Repo::Base],
        &mut builder,
    );
    assert!(matches!(refused, Err(MapError::VersionMismatch { .. })));

    // The builder is exactly as it was found, which is the half that matters. A caller that ignores
    // the error gets a map that knows nothing, and a map that knows nothing judges nothing. Had the
    // exhaustiveness claim been made against the builder before the check, that same map would say
    // every file in the install is one a mod tool put there.
    let map = builder.build();
    assert!(map.is_empty());
    assert!(!map.accounts_for(Repo::Base));
    let blind = game.detect_mods(&map, &ModOptions::default());
    assert_eq!(blind.would_be_replaced(), 0);
    assert!(blind.totals.unknown > 0);
    assert!(!blind.is_exhaustive());

    // The same index at the version it was built for describes the whole tree.
    let mut builder = PristineMap::builder();
    describe_containers(&index, &report, VERSION, &[Repo::Base], &mut builder)?;
    let good = builder.build();
    assert!(!good.is_empty());
    assert!(good.accounts_for(Repo::Base));
    Ok(())
}
