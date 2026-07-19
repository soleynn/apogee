//! The repair gate: damage an installed tree, verify, repair through a `RangeSource`, and confirm the
//! tree is byte-identical again while only the broken ranges were pulled. The property gate zeroes
//! random 128-byte blocks across the tree 1000× and re-heals each time.
//!
//! The chain mirrors `index_verify.rs` so repair sees every part shape: stored and compressed `F:A`
//! whole-file adds, a compressed part split by a later interior write (so two broken halves share one
//! source block), an `H` header, a `D`/`E` empty block, and an `F:D` delete.

mod support;

use std::io::Cursor;
use std::path::{Path, PathBuf};

use apogee_test_support::tree_manifest;
use apogee_zipatch::{
    ApplyOptions, DiskSink, Error, Index, LocalPatchSource, PatchReader, Platform, VerifyOptions,
    apply, build_index,
};
use support::{CountingSource, PatchBuilder, block_deflate, block_stored, splitmix64};

const WIN32: u16 = 0;
/// The base-game dat and its file-target triple.
const DAT0: (u16, u16, u32) = (0x0a, 0x0000, 0);
const DAT0_PATH: &str = "sqpack/ffxiv/0a0000.win32.dat0";

/// First patch: seed a dat with an `A` write superseded-and-extended by an `H` header, and add a
/// stored+compressed exe, a small file later deleted, and a compressed dat.
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

/// Second patch: overwrite the middle of the dat, expand it with an `E` empty block, delete
/// `old.txt`, and continue `data.bin` at an interior offset (splitting the compressed part).
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

/// Overwrite a byte range of a file with `fill` (whole-file read/modify/write; the fixtures are tiny).
fn overwrite(path: &Path, off: usize, fill: &[u8]) -> std::io::Result<()> {
    let mut data = std::fs::read(path)?;
    data[off..off + fill.len()].copy_from_slice(fill);
    std::fs::write(path, data)
}

/// Zero `len` bytes of a file at `off`.
fn zero_range(path: &Path, off: usize, len: usize) -> std::io::Result<()> {
    overwrite(path, off, &vec![0u8; len])
}

/// Set up an applied tree and its index; returns (tempdir, index, baseline manifest).
#[allow(clippy::type_complexity)]
fn setup(
    patches: &[Vec<u8>],
) -> Result<(tempfile::TempDir, Index, tree_manifest::TreeManifest), Box<dyn std::error::Error>> {
    let applied = tempfile::tempdir()?;
    apply_chain(applied.path(), patches)?;
    let index = build_from(patches)?;
    let baseline = tree_manifest::author(applied.path())?;
    Ok((applied, index, baseline))
}

#[test]
fn repair_restores_a_flipped_byte_pulling_only_its_part() {
    let chain = chain();
    let (applied, index, baseline) = setup(&chain).expect("setup");

    // Corrupt the first byte of ffxivboot.exe's [0,100) stored part.
    overwrite(&applied.path().join("ffxivboot.exe"), 0, &[0xFF]).expect("corrupt");
    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(!report.is_clean());

    let mut source = CountingSource::new(chain.clone());
    let outcome = index
        .repair(applied.path(), &report, &mut source)
        .expect("repair");

    assert!(
        outcome.is_complete(),
        "still broken: {:?}",
        outcome.still_broken
    );
    // The stored part is 100 bytes; a one-byte flip pulls exactly its part, nothing more.
    assert_eq!(outcome.bytes_fetched, 100);
    assert_eq!(source.bytes_served, 100);

    let now = tree_manifest::author(applied.path()).expect("author");
    assert_eq!(
        now.files, baseline.files,
        "repaired tree must match baseline"
    );
}

#[test]
fn repair_pulls_only_the_corrupted_ranges() {
    let chain = chain();
    let (applied, index, baseline) = setup(&chain).expect("setup");

    // Two far-apart stored parts in two different patches: ffxivboot.exe[0,100) (patch 0, 100 B) and
    // the dat's [256,384) 0x33 write (patch 1, 128 B).
    overwrite(&applied.path().join("ffxivboot.exe"), 0, &[0xFF]).expect("corrupt boot");
    overwrite(&applied.path().join(DAT0_PATH), 256, &[0xFF]).expect("corrupt dat");
    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");

    let mut source = CountingSource::new(chain.clone());
    let outcome = index
        .repair(applied.path(), &report, &mut source)
        .expect("repair");

    assert!(outcome.is_complete());
    assert_eq!(source.bytes_served, 100 + 128);
    assert_eq!(outcome.bytes_fetched, source.bytes_served);
    // One range per patch, and each patch fetched separately.
    assert_eq!(source.ranges.len(), 2);
    assert_eq!(source.ranges_for(0), 1);
    assert_eq!(source.ranges_for(1), 1);
    // Far less than the whole patch set.
    let total: usize = chain.iter().map(Vec::len).sum();
    assert!(
        (source.bytes_served as usize) < total,
        "served {} of {total} total patch bytes",
        source.bytes_served
    );

    let now = tree_manifest::author(applied.path()).expect("author");
    assert_eq!(now.files, baseline.files);
}

#[test]
fn repair_fetches_a_shared_compressed_block_once() {
    let chain = chain();
    let (applied, index, baseline) = setup(&chain).expect("setup");

    // data.bin's compressed block backs both [0,128) and [192,400) (patch 1's stored [128,192) splits
    // it). Corrupt both halves; the planner must pull the shared block a single time.
    overwrite(&applied.path().join("data.bin"), 0, &[0xFF]).expect("corrupt head");
    overwrite(&applied.path().join("data.bin"), 192, &[0xFF]).expect("corrupt tail");
    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");

    let mut source = CountingSource::new(chain.clone());
    let outcome = index
        .repair(applied.path(), &report, &mut source)
        .expect("repair");

    assert!(outcome.is_complete());
    // Only patch 0 (the compressed block) is fetched, and only once for both halves.
    assert_eq!(source.ranges.len(), 1);
    assert_eq!(source.ranges_for(0), 1);
    // The compressed block is smaller than its 400 decoded bytes.
    assert!(source.bytes_served < 400, "served {}", source.bytes_served);

    let now = tree_manifest::author(applied.path()).expect("author");
    assert_eq!(now.files, baseline.files);
}

#[test]
fn repair_recreates_a_missing_file() {
    let chain = chain();
    let (applied, index, baseline) = setup(&chain).expect("setup");

    std::fs::remove_file(applied.path().join("data.bin")).expect("remove");
    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert_eq!(report.missing_files, vec![PathBuf::from("data.bin")]);

    let mut source = CountingSource::new(chain.clone());
    let outcome = index
        .repair(applied.path(), &report, &mut source)
        .expect("repair");

    assert!(outcome.is_complete());
    assert_eq!(outcome.recreated, vec![PathBuf::from("data.bin")]);

    let now = tree_manifest::author(applied.path()).expect("author");
    assert_eq!(now.files, baseline.files);
}

#[test]
fn repair_truncates_an_over_long_file_without_fetching() {
    let chain = chain();
    let (applied, index, baseline) = setup(&chain).expect("setup");

    // Append garbage past the indexed length: a size mismatch with no broken content parts.
    let dat = applied.path().join(DAT0_PATH);
    let mut grown = std::fs::read(&dat).expect("read");
    grown.extend_from_slice(&[0xEEu8; 512]);
    std::fs::write(&dat, grown).expect("grow");
    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(report.broken.is_empty());
    assert_eq!(report.size_mismatches.len(), 1);

    let mut source = CountingSource::new(chain.clone());
    let outcome = index
        .repair(applied.path(), &report, &mut source)
        .expect("repair");

    assert!(outcome.is_complete());
    assert_eq!(outcome.resized, vec![PathBuf::from(DAT0_PATH)]);
    assert_eq!(outcome.bytes_fetched, 0, "a resize fetches nothing");

    let now = tree_manifest::author(applied.path()).expect("author");
    assert_eq!(now.files, baseline.files);
}

#[test]
fn repair_reconstructs_a_zero_run_without_fetching() {
    // A single patch that writes at offset 128 leaves a leading [0,128) zero run in the tiling.
    let patch = {
        let mut b = PatchBuilder::new();
        b.fhdr(b"DIFF", 0).target_info(WIN32);
        b.add_data(DAT0, 128, &[0x11u8; 128], 0);
        b.eof();
        b.bytes()
    };
    let chain = vec![patch];
    let (applied, index, baseline) = setup(&chain).expect("setup");

    // Corrupt the leading zero region: a zeros part, reconstructed locally with no fetch.
    overwrite(&applied.path().join(DAT0_PATH), 0, &[0xFFu8; 64]).expect("corrupt zeros");
    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(!report.is_clean());

    let mut source = CountingSource::new(chain.clone());
    let outcome = index
        .repair(applied.path(), &report, &mut source)
        .expect("repair");

    assert!(outcome.is_complete());
    assert_eq!(outcome.bytes_fetched, 0, "a zero run needs no source bytes");
    assert!(source.ranges.is_empty());

    let now = tree_manifest::author(applied.path()).expect("author");
    assert_eq!(now.files, baseline.files);
}

#[test]
fn repair_reads_ranges_from_local_patch_files() {
    let chain = chain();
    let (applied, index, baseline) = setup(&chain).expect("setup");

    // Write the patches to disk and repair through the on-disk LocalPatchSource.
    let patch_dir = tempfile::tempdir().expect("patch dir");
    let paths = write_patches(patch_dir.path(), &chain).expect("write patches");

    overwrite(&applied.path().join("ffxivboot.exe"), 50, &[0xFF]).expect("corrupt");
    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");

    let mut source = LocalPatchSource::new(paths);
    let outcome = index
        .repair(applied.path(), &report, &mut source)
        .expect("repair");
    assert!(outcome.is_complete());

    let now = tree_manifest::author(applied.path()).expect("author");
    assert_eq!(now.files, baseline.files);
}

#[test]
fn zeroing_random_blocks_and_repairing_is_identical_a_thousand_times() {
    let chain = chain();
    let (applied, index, baseline) = setup(&chain).expect("setup");
    let root = applied.path();

    let patch_dir = tempfile::tempdir().expect("patch dir");
    let paths = write_patches(patch_dir.path(), &chain).expect("write patches");
    let mut source = LocalPatchSource::new(paths);

    let files = ["ffxivboot.exe", "data.bin", DAT0_PATH];
    let mut state = 0x5EED_1234_C0FF_EE01u64;
    for iter in 0..1000u32 {
        // Zero 1..=3 random 128-byte-aligned blocks across the tree.
        let corruptions = 1 + splitmix64(&mut state) % 3;
        for _ in 0..corruptions {
            let file = files[(splitmix64(&mut state) % files.len() as u64) as usize];
            let abs = root.join(file);
            let len = std::fs::metadata(&abs).expect("metadata").len();
            if len == 0 {
                continue;
            }
            let blocks = len.div_ceil(128);
            let off = (splitmix64(&mut state) % blocks) * 128;
            let n = (len - off).min(128);
            zero_range(&abs, off as usize, n as usize).expect("zero");
        }

        let report = index
            .verify(root, &VerifyOptions::default())
            .expect("verify");
        if report.is_clean() {
            // The corruption only re-zeroed already-zero bytes; nothing to repair.
            continue;
        }
        let outcome = index.repair(root, &report, &mut source).expect("repair");
        assert!(
            outcome.is_complete(),
            "iteration {iter} left parts broken: {:?}",
            outcome.still_broken
        );
        let now = tree_manifest::author(root).expect("author");
        assert_eq!(
            now.files, baseline.files,
            "iteration {iter} diverged from baseline"
        );
    }
}

/// Write each patch to `dir` as `p{i}.patch`, returning the paths in chain order (so `paths[i]` backs
/// `PatchId(i)`).
fn write_patches(dir: &Path, patches: &[Vec<u8>]) -> std::io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for (i, patch) in patches.iter().enumerate() {
        let path = dir.join(format!("p{i}.patch"));
        std::fs::write(&path, patch)?;
        paths.push(path);
    }
    Ok(paths)
}
