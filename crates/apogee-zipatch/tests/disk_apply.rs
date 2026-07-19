//! [`DiskSink`] against a real scratch tree: parent-dir creation, overwrite truncation, the
//! delete-missing no-op, and symlink-escape refusal.

mod support;

use std::path::Path;

use apogee_zipatch::{ApplyOptions, Chunk, DiskSink, Error, Limit, PatchReader, Sqpk, apply};

use support::{
    PatchBuilder, block_bad_deflate, block_deflate, block_deflate_claiming, block_stored,
    empty_block_header,
};

/// The base-game dat `sqpack/ffxiv/0a0000.win32.dat0` and its file-target triple.
const DAT0: (u16, u16, u32) = (0x0a, 0x0000, 0);
const DAT0_PATH: &str = "sqpack/ffxiv/0a0000.win32.dat0";

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

#[test]
fn add_data_writes_bytes_then_zeroes_the_delete_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Write 128 bytes into a fresh dat, then wipe the next 128 (a plain tail wipe, no header).
    let patch = boot_patch(|b| {
        b.add_data(DAT0, 0, &[0x55; 128], 128);
    });
    apply_patch(dir.path(), &patch).expect("apply");

    let mut expected = vec![0x55u8; 128];
    expected.extend_from_slice(&[0u8; 128]);
    assert_eq!(std::fs::read(dir.path().join(DAT0_PATH)).unwrap(), expected);
}

#[test]
fn delete_data_stamps_a_24_byte_header_over_a_zeroed_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Lay a 512-byte dat of 0xEE, then delete two 128-byte blocks starting at offset 128.
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 512, DAT0_PATH, &block_stored(&[0xEE; 512]))
            .empty_block(b'D', DAT0, 128, 2);
    });
    apply_patch(dir.path(), &patch).expect("apply");

    let mut expected = vec![0xEEu8; 512];
    // The 256-byte run [128, 384) is zeroed, then the 24-byte header overwrites its start.
    for b in &mut expected[128..384] {
        *b = 0;
    }
    expected[128..152].copy_from_slice(&empty_block_header(2));
    assert_eq!(std::fs::read(dir.path().join(DAT0_PATH)).unwrap(), expected);
}

#[test]
fn expand_data_writes_the_same_bytes_as_delete_data() {
    // D and E share the reference implementation, so the same command yields the same dat bytes.
    let build = |cmd: u8| {
        boot_patch(|b| {
            b.file_op(b'A', 0, 512, DAT0_PATH, &block_stored(&[0xEE; 512]))
                .empty_block(cmd, DAT0, 128, 3);
        })
    };
    let with_delete = tempfile::tempdir().expect("tempdir");
    let with_expand = tempfile::tempdir().expect("tempdir");
    apply_patch(with_delete.path(), &build(b'D')).expect("apply D");
    apply_patch(with_expand.path(), &build(b'E')).expect("apply E");

    assert_eq!(
        std::fs::read(with_delete.path().join(DAT0_PATH)).unwrap(),
        std::fs::read(with_expand.path().join(DAT0_PATH)).unwrap(),
    );
}

#[test]
fn empty_block_with_zero_count_still_stamps_the_header() {
    // The block_count == 0 edge is the only case whose bytes distinguish the 24-byte header from a
    // mistaken 20-byte one: the wipe is empty, but the header still lands and the file extends to 24.
    let dir = tempfile::tempdir().expect("tempdir");
    let patch = boot_patch(|b| {
        b.empty_block(b'D', DAT0, 0, 0);
    });
    apply_patch(dir.path(), &patch).expect("apply");
    assert_eq!(
        std::fs::read(dir.path().join(DAT0_PATH)).unwrap(),
        empty_block_header(0),
    );
}

#[test]
fn expand_past_eof_grows_with_a_sparse_zero_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A 128-byte dat, then expand 4 blocks (512 bytes) starting at the current EOF. The whole run is
    // beyond EOF, so it is a sparse `set_len` extend rather than an explicit zero write; the content
    // still reads back as the header followed by zeros.
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 128, DAT0_PATH, &block_stored(&[0xEE; 128]))
            .empty_block(b'E', DAT0, 128, 4);
    });
    apply_patch(dir.path(), &patch).expect("apply");

    let dat = std::fs::read(dir.path().join(DAT0_PATH)).unwrap();
    let mut expected = vec![0xEEu8; 128];
    expected.extend_from_slice(&empty_block_header(4)); // header lands at offset 128
    expected.resize(128 + 512, 0); // the rest of the 512-byte run reads as zeros
    assert_eq!(dat, expected);
}

#[test]
fn header_writes_1024_bytes_at_version_and_data_offsets() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A version header lands at offset 0 of the index file; a data header at offset 1024 of the dat,
    // leaving the first 1024 bytes a zero hole.
    let patch = boot_patch(|b| {
        b.header(b'I', b'V', DAT0, &[0x77; 1024])
            .header(b'D', b'D', DAT0, &[0x66; 1024]);
    });
    apply_patch(dir.path(), &patch).expect("apply");

    let index = std::fs::read(dir.path().join("sqpack/ffxiv/0a0000.win32.index")).unwrap();
    assert_eq!(index, vec![0x77u8; 1024]);

    let dat = std::fs::read(dir.path().join(DAT0_PATH)).unwrap();
    let mut expected = vec![0u8; 1024];
    expected.extend_from_slice(&[0x66u8; 1024]);
    assert_eq!(dat, expected);
}

#[test]
fn remove_all_deletes_non_kept_files_and_spares_var_and_movies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let sqpack = root.join("sqpack/ex1");
    let movie = root.join("movie/ex1");
    let other = root.join("sqpack/ffxiv");
    std::fs::create_dir_all(&sqpack).unwrap();
    std::fs::create_dir_all(&movie).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(sqpack.join("0c0100.win32.dat0"), b"x").unwrap(); // deleted
    std::fs::write(sqpack.join("0c0100.win32.index"), b"x").unwrap(); // deleted
    std::fs::write(sqpack.join("ffxivgame.var"), b"x").unwrap(); // spared (.var)
    std::fs::write(movie.join("00000.bk2"), b"x").unwrap(); // spared (intro movie)
    std::fs::write(movie.join("00004.bk2"), b"x").unwrap(); // deleted
    std::fs::write(movie.join("ending.bk2"), b"x").unwrap(); // deleted
    std::fs::write(other.join("0a0000.win32.dat0"), b"x").unwrap(); // other expansion, untouched

    let patch = boot_patch(|b| {
        b.removeall(1, "sqpack/ex1");
    });
    apply_patch(root, &patch).expect("apply removeall");

    assert!(!sqpack.join("0c0100.win32.dat0").exists());
    assert!(!sqpack.join("0c0100.win32.index").exists());
    assert!(
        sqpack.join("ffxivgame.var").exists(),
        "a .var must be spared"
    );
    assert!(
        movie.join("00000.bk2").exists(),
        "an intro movie must be spared"
    );
    assert!(!movie.join("00004.bk2").exists());
    assert!(!movie.join("ending.bk2").exists());
    assert!(
        other.join("0a0000.win32.dat0").exists(),
        "another expansion must be untouched"
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
