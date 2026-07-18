//! [`DiskSink`] against a real scratch tree: parent-dir creation, overwrite truncation, the
//! delete-missing no-op, and symlink-escape refusal.

mod support;

use std::path::Path;

use apogee_zipatch::{ApplyOptions, DiskSink, Error, PatchReader, apply};

use support::{PatchBuilder, block_deflate, block_stored};

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
