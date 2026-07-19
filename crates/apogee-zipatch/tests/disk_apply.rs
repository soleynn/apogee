//! [`DiskSink`] against a real scratch tree: parent-dir creation, overwrite truncation, the
//! delete-missing no-op, and symlink-escape refusal.

mod support;

use std::path::Path;

use apogee_zipatch::{ApplyOptions, Chunk, DiskSink, Error, Limit, PatchReader, Sqpk, apply};

use support::{
    PatchBuilder, block_bad_deflate, block_deflate, block_deflate_claiming, block_stored,
};

/// Parse `patch` and return the first `SQPK F:A` block stream's absolute patch offset.
fn add_file_blocks_off(patch: &[u8]) -> Result<u64, Error> {
    let mut reader = PatchReader::open(patch)?;
    while let Some(chunk) = reader.next_chunk()? {
        if let Chunk::Sqpk(Sqpk::File(f)) = chunk {
            return Ok(f.blocks_off);
        }
    }
    Ok(0)
}

const WIN32: u16 = 0;

/// Apply a whole patch under `root` with a fresh sink (one apply per patch, as the patcher does).
fn apply_patch(root: &Path, patch: &[u8]) -> Result<(), Error> {
    let mut reader = PatchReader::open(patch)?;
    let mut sink = DiskSink::new(root)?;
    apply(&mut reader, &mut sink, &ApplyOptions::default())
}

fn boot_patch(build: impl FnOnce(&mut PatchBuilder)) -> Vec<u8> {
    let mut b = PatchBuilder::new();
    b.fhdr(b"DIFF", 1).target_info(WIN32);
    build(&mut b);
    b.eof();
    b.bytes()
}

#[test]
fn writes_files_and_creates_parent_dirs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let nested = b"nested payload".repeat(4);
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 4, "top.bin", &block_stored(b"TOP!"))
            // A file under a directory that no ADIR chunk created (boot's `locales/` case).
            .file_op(
                b'A',
                0,
                nested.len() as i64,
                "locales/fileinfo.fiin",
                &block_deflate(&nested),
            );
    });
    apply_patch(dir.path(), &patch).expect("apply");

    assert_eq!(std::fs::read(dir.path().join("top.bin")).unwrap(), b"TOP!");
    assert_eq!(
        std::fs::read(dir.path().join("locales/fileinfo.fiin")).unwrap(),
        nested
    );
}

#[test]
fn an_offset_zero_add_truncates_the_existing_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    // First patch lays down a long file; a second overwrites it with shorter content at offset 0.
    apply_patch(
        dir.path(),
        &boot_patch(|b| {
            b.file_op(b'A', 0, 8, "app.exe", &block_stored(b"LONGDATA"));
        }),
    )
    .expect("apply 1");
    apply_patch(
        dir.path(),
        &boot_patch(|b| {
            b.file_op(b'A', 0, 3, "app.exe", &block_stored(b"NEW"));
        }),
    )
    .expect("apply 2");

    assert_eq!(std::fs::read(dir.path().join("app.exe")).unwrap(), b"NEW");
}

#[test]
fn deleting_a_file_that_was_never_created_is_a_noop() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The 2026 boot patch deletes files a base link never laid down; that must succeed cleanly.
    let patch = boot_patch(|b| {
        b.file_op(b'D', 0, 0, "ffxivconfig.exe", &[]);
    });
    apply_patch(dir.path(), &patch).expect("delete-missing is a no-op");
    assert!(!dir.path().join("ffxivconfig.exe").exists());
}

#[test]
fn deletes_an_existing_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 2, "gone.bin", &block_stored(b"hi"))
            .file_op(b'D', 0, 0, "gone.bin", &[]);
    });
    apply_patch(dir.path(), &patch).expect("apply");
    assert!(!dir.path().join("gone.bin").exists());
}

#[cfg(unix)]
#[test]
fn a_symlinked_parent_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    // Plant an in-tree symlink where a later write's parent directory would be created.
    std::os::unix::fs::symlink(outside.path(), dir.path().join("locales")).expect("symlink");

    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 4, "locales/x.txt", &block_stored(b"evil"));
    });
    assert!(matches!(
        apply_patch(dir.path(), &patch),
        Err(Error::PathEscape { .. })
    ));
    // The write never escaped into the symlink target.
    assert!(!outside.path().join("x.txt").exists());
}

#[test]
fn a_continuation_survives_handle_eviction() {
    let dir = tempfile::tempdir().expect("tempdir");
    // One apply, one handle store: write a.dat's head, fill the 16-handle store with other files to
    // evict a.dat, then continue a.dat at offset 4. The reopen must not truncate, or the head is lost.
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 4, "a.dat", &block_stored(b"HEAD"));
        for i in 0..20 {
            b.file_op(
                b'A',
                0,
                4,
                &format!("filler{i}.dat"),
                &block_stored(b"----"),
            );
        }
        b.file_op(b'A', 4, 4, "a.dat", &block_stored(b"TAIL"));
    });
    apply_patch(dir.path(), &patch).expect("apply");
    assert_eq!(
        std::fs::read(dir.path().join("a.dat")).unwrap(),
        b"HEADTAIL"
    );
}

#[test]
fn an_over_cap_block_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    // One past MAX_BLOCK_DECOMPRESSED; the decode cap must reject it before allocating.
    let over = (16u32 << 20) + 1;
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 1, "big.dat", &block_deflate_claiming(b"x", over));
    });
    assert!(matches!(
        apply_patch(dir.path(), &patch),
        Err(Error::LimitExceeded {
            what: Limit::BlockSize,
            ..
        })
    ));
}

#[test]
fn a_corrupt_deflate_block_reports_a_patch_absolute_offset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 8, "x.dat", &block_bad_deflate(8, 8));
    });
    // The DEFLATE payload begins 16 bytes past the block stream (after the block header).
    let payload_off = add_file_blocks_off(&patch).expect("parse") + 16;
    match apply_patch(dir.path(), &patch) {
        Err(Error::Corrupt { offset, .. }) => assert_eq!(offset, payload_off),
        other => panic!("expected Corrupt at {payload_off}, got {other:?}"),
    }
}

#[test]
fn makes_and_removes_a_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let make = boot_patch(|b| {
        b.add_directory("extra")
            .file_op(b'A', 0, 2, "extra/f.bin", &block_stored(b"hi"));
    });
    apply_patch(dir.path(), &make).expect("apply make");
    assert!(dir.path().join("extra/f.bin").exists());

    let remove = boot_patch(|b| {
        b.delete_directory("extra");
    });
    apply_patch(dir.path(), &remove).expect("apply remove");
    assert!(!dir.path().join("extra").exists());
}

#[cfg(unix)]
#[test]
fn a_symlinked_parent_blocks_a_file_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(outside.path().join("secret"), b"keep").unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("mods")).expect("symlink");

    let patch = boot_patch(|b| {
        b.file_op(b'D', 0, 0, "mods/secret", &[]);
    });
    assert!(matches!(
        apply_patch(dir.path(), &patch),
        Err(Error::PathEscape { .. })
    ));
    assert!(
        outside.path().join("secret").exists(),
        "the delete escaped the root through an in-tree symlink"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_target_blocks_a_recursive_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(outside.path().join("keep"), b"x").unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("mods")).expect("symlink");

    let patch = boot_patch(|b| {
        b.delete_directory("mods");
    });
    assert!(matches!(
        apply_patch(dir.path(), &patch),
        Err(Error::PathEscape { .. })
    ));
    assert!(
        outside.path().join("keep").exists(),
        "the recursive delete followed the symlink out of the root"
    );
}
