//! The block-index gate: an index built over a patch chain reconstructs a tree byte-identical to
//! applying the chain (`apply ≡ reconstruct_from(index)`), and verifying a healthy tree against the
//! index reports nothing broken. Also exercises the break/missing/size/stray/refine report paths.
//!
//! The chain is built with the shared `support` helpers so it exercises every command the index must
//! model: `A` raw writes, an `H` header that supersedes and extends an earlier write, `F:A` stored
//! and compressed whole-file adds, a `F:A` continuation that splits an existing compressed part, a
//! `D`/`E` empty-block expand, and an `F:D` delete.

mod support;

use std::io::Cursor;
use std::path::Path;

use apogee_test_support::tree_manifest;
use apogee_zipatch::{
    ApplyOptions, DiskSink, Error, Index, PatchReader, Platform, VerifyOptions, apply, build_index,
};
use support::{PatchBuilder, block_deflate, block_stored};

const WIN32: u16 = 0;
/// The base-game dat `sqpack/ffxiv/0a0000.win32.dat0` and its file-target triple.
const DAT0: (u16, u16, u32) = (0x0a, 0x0000, 0);

/// The first patch: seed a dat with an `A` write then supersede-and-extend it with an `H` header, and
/// add three whole files (a stored+compressed exe, a small file later deleted, a compressed dat).
fn patch_a() -> Vec<u8> {
    let mut b = PatchBuilder::new();
    b.fhdr(b"DIFF", 0).target_info(WIN32);
    b.add_data(DAT0, 0, &[0x11u8; 384], 0);
    b.header(b'D', b'V', DAT0, &[0x22u8; 1024]);
    let boot = [block_stored(&[0xABu8; 100]), block_deflate(&[0xCDu8; 200])].concat();
    b.file_op(b'A', 0, 300, "ffxivboot.exe", &boot);
    b.file_op(b'A', 0, 10, "old.txt", &block_stored(&[0x77u8; 10]));
    b.file_op(b'A', 0, 400, "data.bin", &block_deflate(&[0x55u8; 400]));
    b.eof();
    b.bytes()
}

/// The second patch: overwrite the middle of the dat (splitting the header part), expand it with an
/// `E` empty block, delete `old.txt`, and continue `data.bin` at an interior offset (splitting the
/// compressed part so its remnant carries a non-zero decoded offset).
fn patch_b() -> Vec<u8> {
    let mut b = PatchBuilder::new();
    b.fhdr(b"DIFF", 0).target_info(WIN32);
    b.add_data(DAT0, 256, &[0x33u8; 128], 0);
    b.empty_block(b'E', DAT0, 1024, 4);
    b.file_op(b'D', 0, 0, "old.txt", &[]);
    b.file_op(b'A', 128, 0, "data.bin", &block_stored(&[0x99u8; 64]));
    b.eof();
    b.bytes()
}

fn chain() -> Vec<Vec<u8>> {
    vec![patch_a(), patch_b()]
}

/// Apply a chain under `root`, one fresh sink per patch (as the patcher runs them).
fn apply_chain(root: &Path, patches: &[Vec<u8>]) -> Result<(), Error> {
    for patch in patches {
        let mut reader = PatchReader::open(Cursor::new(patch.clone()))?.verify_crc(true);
        let mut sink = DiskSink::new(root)?;
        apply(&mut reader, &mut sink, &ApplyOptions::default())?;
    }
    Ok(())
}

/// Build an index over a chain (each patch a seekable in-memory source).
fn build_from(patches: &[Vec<u8>]) -> Result<Index, Error> {
    let inputs: Vec<(String, Cursor<Vec<u8>>)> = patches
        .iter()
        .enumerate()
        .map(|(i, p)| (format!("p{i}.patch"), Cursor::new(p.clone())))
        .collect();
    build_index(inputs, Platform::Win32, "test-version")
}

/// Fresh seekable readers over the same patches, in chain order (what reconstruct expects).
fn sources(patches: &[Vec<u8>]) -> Vec<Cursor<Vec<u8>>> {
    patches.iter().map(|p| Cursor::new(p.clone())).collect()
}

#[test]
fn reconstruct_from_index_equals_apply() {
    let chain = chain();

    let applied = tempfile::tempdir().expect("tempdir");
    apply_chain(applied.path(), &chain).expect("apply chain");

    let index = build_from(&chain).expect("build index");
    let rebuilt = tempfile::tempdir().expect("tempdir");
    index
        .reconstruct(rebuilt.path(), &mut sources(&chain))
        .expect("reconstruct");

    let applied_tree = tree_manifest::author(applied.path()).expect("author applied");
    let rebuilt_tree = tree_manifest::author(rebuilt.path()).expect("author rebuilt");
    assert_eq!(
        applied_tree.files, rebuilt_tree.files,
        "reconstructed tree must be byte-identical to the applied tree"
    );
    // The deleted file is absent from both trees.
    assert!(applied_tree.files.iter().all(|f| f.path != "old.txt"));
    // Every command's file survives the round trip.
    for name in [
        "ffxivboot.exe",
        "data.bin",
        "sqpack/ffxiv/0a0000.win32.dat0",
    ] {
        assert!(
            rebuilt_tree.files.iter().any(|f| f.path == name),
            "expected {name} in the reconstructed tree"
        );
    }
}

#[test]
fn verify_of_a_healthy_tree_is_clean() {
    let chain = chain();
    let applied = tempfile::tempdir().expect("tempdir");
    apply_chain(applied.path(), &chain).expect("apply chain");
    let index = build_from(&chain).expect("build index");

    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(report.is_clean(), "expected a clean tree, got {report:?}");
}

#[test]
fn a_flipped_byte_breaks_exactly_its_part() {
    let chain = chain();
    let applied = tempfile::tempdir().expect("tempdir");
    apply_chain(applied.path(), &chain).expect("apply chain");
    let index = build_from(&chain).expect("build index");

    let boot = applied.path().join("ffxivboot.exe");
    let mut data = std::fs::read(&boot).expect("read");
    data[0] ^= 0xFF; // corrupt the first stored block
    std::fs::write(&boot, &data).expect("write");

    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(
        report
            .broken
            .iter()
            .any(|p| p.path == Path::new("ffxivboot.exe") && p.target_off == 0),
        "expected the [0,..) part of ffxivboot.exe broken, got {:?}",
        report.broken
    );
    assert!(report.missing_files.is_empty());
    assert!(report.stray_files.is_empty());
}

#[test]
fn a_truncated_file_is_a_size_mismatch() {
    let chain = chain();
    let applied = tempfile::tempdir().expect("tempdir");
    apply_chain(applied.path(), &chain).expect("apply chain");
    let index = build_from(&chain).expect("build index");

    let dat = applied.path().join("sqpack/ffxiv/0a0000.win32.dat0");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&dat)
        .expect("open");
    file.set_len(100).expect("truncate");

    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(
        report
            .size_mismatches
            .iter()
            .any(|m| m.path == Path::new("sqpack/ffxiv/0a0000.win32.dat0") && m.actual == 100),
        "expected a size mismatch, got {:?}",
        report.size_mismatches
    );
}

#[test]
fn a_deleted_file_is_reported_missing() {
    let chain = chain();
    let applied = tempfile::tempdir().expect("tempdir");
    apply_chain(applied.path(), &chain).expect("apply chain");
    let index = build_from(&chain).expect("build index");

    std::fs::remove_file(applied.path().join("data.bin")).expect("remove");
    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert_eq!(
        report.missing_files,
        vec![Path::new("data.bin").to_path_buf()]
    );
}

#[test]
fn an_unindexed_file_is_a_stray_unless_ignored() {
    let chain = chain();
    let applied = tempfile::tempdir().expect("tempdir");
    apply_chain(applied.path(), &chain).expect("apply chain");
    let index = build_from(&chain).expect("build index");

    std::fs::write(applied.path().join("extra.bin"), b"not indexed").expect("write stray");
    std::fs::write(applied.path().join("ffxivgame.ver"), b"1970").expect("write ver");

    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(
        report
            .stray_files
            .iter()
            .any(|s| s.path == Path::new("extra.bin")),
        "expected extra.bin flagged, got {:?}",
        report.stray_files
    );
    assert!(
        report
            .stray_files
            .iter()
            .all(|s| s.path != Path::new("ffxivgame.ver")),
        "a .ver file must be excused, got {:?}",
        report.stray_files
    );
}

#[test]
fn refine_rechecks_only_the_given_parts() {
    let chain = chain();
    let applied = tempfile::tempdir().expect("tempdir");
    apply_chain(applied.path(), &chain).expect("apply chain");
    let index = build_from(&chain).expect("build index");

    let boot = applied.path().join("ffxivboot.exe");
    let mut data = std::fs::read(&boot).expect("read");
    let original = data[0];
    data[0] ^= 0xFF;
    std::fs::write(&boot, &data).expect("write");

    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(!report.broken.is_empty());

    // Repair the byte and re-check only the broken parts: the retry loop that must not re-hash the
    // whole tree.
    data[0] = original;
    std::fs::write(&boot, &data).expect("restore");
    let refined = index
        .verify(
            applied.path(),
            &VerifyOptions {
                parallelism: None,
                refine: Some(&report.broken),
            },
        )
        .expect("refine verify");
    assert!(
        refined.broken.is_empty(),
        "refine should find the repaired parts clean, got {:?}",
        refined.broken
    );
}

#[test]
fn refine_reports_a_vanished_file_as_broken() {
    let chain = chain();
    let applied = tempfile::tempdir().expect("tempdir");
    apply_chain(applied.path(), &chain).expect("apply chain");
    let index = build_from(&chain).expect("build index");

    // A full pass over a corrupted file gives the broken part refs.
    let boot = applied.path().join("ffxivboot.exe");
    let mut data = std::fs::read(&boot).expect("read");
    data[0] ^= 0xFF;
    std::fs::write(&boot, &data).expect("write");
    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(!report.broken.is_empty());

    // Now the file vanishes before the retry: refine must re-break its referenced parts, not skip
    // them (a repair that then re-fetches them).
    std::fs::remove_file(&boot).expect("remove");
    let refined = index
        .verify(
            applied.path(),
            &VerifyOptions {
                parallelism: None,
                refine: Some(&report.broken),
            },
        )
        .expect("refine verify");
    assert!(
        refined
            .broken
            .iter()
            .any(|p| p.path == Path::new("ffxivboot.exe")),
        "a vanished file's referenced parts must stay broken under refine, got {:?}",
        refined.broken
    );
}

#[test]
fn an_empty_block_split_reconstructs_and_verifies() {
    // Patch 1 seeds a dat and expands it with an `E` empty block; patch 2 overwrites the middle of
    // that empty-block region, splitting it so its remnants carry decoded offsets. Reconstruct must
    // match apply and verify must stay clean.
    let patch1 = {
        let mut b = PatchBuilder::new();
        b.fhdr(b"DIFF", 0).target_info(WIN32);
        b.add_data(DAT0, 0, &[0x11u8; 128], 0);
        b.empty_block(b'E', DAT0, 128, 4); // empty-block region [128, 640)
        b.eof();
        b.bytes()
    };
    let patch2 = {
        let mut b = PatchBuilder::new();
        b.fhdr(b"DIFF", 0).target_info(WIN32);
        b.add_data(DAT0, 256, &[0x99u8; 128], 0); // overwrite inside the empty-block region
        b.eof();
        b.bytes()
    };
    let chain = vec![patch1, patch2];

    let applied = tempfile::tempdir().expect("tempdir");
    apply_chain(applied.path(), &chain).expect("apply chain");
    let index = build_from(&chain).expect("build index");

    let rebuilt = tempfile::tempdir().expect("tempdir");
    index
        .reconstruct(rebuilt.path(), &mut sources(&chain))
        .expect("reconstruct");
    let applied_tree = tree_manifest::author(applied.path()).expect("author applied");
    let rebuilt_tree = tree_manifest::author(rebuilt.path()).expect("author rebuilt");
    assert_eq!(applied_tree.files, rebuilt_tree.files);

    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(report.is_clean(), "expected clean, got {report:?}");
}
