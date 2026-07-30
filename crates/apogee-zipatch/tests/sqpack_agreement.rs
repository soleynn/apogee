//! The two crates against each other, over one tree.
//!
//! `apogee-zipatch` writes the bytes and `apogee-sqpack` reads them. They already share the block
//! codec, so a compressed payload cannot be encoded one way and decoded another, but nothing had
//! ever applied a patch and then opened the result as an archive. Everything between the two, the
//! entry layout, the index a lookup binary-searches, the offsets a location word packs, was only
//! ever exercised by each crate against its own fixtures.
//!
//! What is asserted here is the format half: every file the patch wrote resolves through a real
//! index and decodes to the bytes that went in, both index forms agree on where each one is, and the
//! structural sweep finds nothing wrong at any tier.
//!
//! The other half, whether a block index and a verification of it can say which files somebody
//! modified, needs a crate that holds both an index and an archive reader; it lives beside the layer
//! that composes them, in `apogee-patcher`.
//!
//! The archive bytes come from `apogee-sqpack`'s own builders, through its `test-fixtures` feature,
//! so the layout has one owner and this file cannot drift from the reader it is checking.

use std::error::Error;

use apogee_sqpack::fixtures::{ArchiveFixture, EntrySpec};
use apogee_sqpack::integrity::SweepOptions;
use apogee_sqpack::{ArchiveId, GameData, IndexKind, MODEL_LOD_COUNT, Repo};
use apogee_zipatch::fixtures;
use apogee_zipatch::fixtures::{PatchBuilder, block_deflate, block_stored};

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
    std::fs::write(tmp.path().join("ffxivgame.ver"), "2026.07.16.0001.0000")?;
    let game = GameData::open(tmp.path())?;
    Ok((tmp, game))
}

#[test]
fn every_file_a_patch_writes_resolves_and_decodes_through_the_reader() -> R<()> {
    let fixtures = archives();
    let (tmp, game) = tree(&[patch_for(&fixtures)])?;

    // The tree is a set of archives, not just a pile of files: the reader enumerates them as such.
    assert_eq!(game.archives().len(), 3);
    assert!(
        game.archives()
            .iter()
            .all(|info| info.has_index1 && info.has_index2 && !info.dats.is_empty())
    );

    let files = expected(&fixtures);
    assert!(files.len() >= 7, "the fixture must carry every entry shape");
    for (path, content) in &files {
        let found = game
            .lookup(path)?
            .unwrap_or_else(|| panic!("{path} did not resolve"));
        assert_eq!(found.repo, Repo::Base);
        let bytes = game
            .read(path)?
            .unwrap_or_else(|| panic!("{path} did not read"));
        assert_eq!(&bytes, content, "{path}");
        // And the second form agrees about where it is, which is the cross-check the reader keeps
        // for exactly this: two independently written tables naming one place.
        let cross = game.lookup_in(path, IndexKind::Index2)?.unwrap();
        assert_eq!(
            (cross.dat, cross.offset),
            (found.dat, found.offset),
            "{path}"
        );
    }

    // Nothing structural disagrees either, at every tier the sweep offers.
    let report = game.inspect(&SweepOptions {
        hash_data_regions: true,
        decode_entries: true,
        ..SweepOptions::default()
    });
    assert!(report.is_clean(), "{:#?}", report.findings);
    assert!(report.is_complete());
    drop(tmp);
    Ok(())
}
