//! The apply interpreter driven by hand-built patches: block framing (stored + deflate), truncate
//! semantics, continuations, deletes, refusals, confinement, cancellation, and progress.

mod support;

use std::sync::atomic::AtomicBool;
use std::sync::mpsc;

use apogee_zipatch::{ApplyOptions, ApplyProgress, Error, PatchReader, apply, scan_crc};

use support::{InMemorySink, PatchBuilder, TraceSink, block_deflate, block_stored};

const WIN32: u16 = 0;
const PS3: u16 = 1;

/// Apply a whole patch into a fresh in-memory tree.
fn apply_to_mem(patch: &[u8]) -> Result<InMemorySink, Error> {
    let mut reader = PatchReader::open(patch)?;
    let mut sink = InMemorySink::default();
    apply(&mut reader, &mut sink, &ApplyOptions::default())?;
    Ok(sink)
}

/// A boot-shaped patch: header, platform, then the given `SQPK F` command bytes already framed by the
/// caller, and `EOF_`.
fn boot_patch(build: impl FnOnce(&mut PatchBuilder)) -> Vec<u8> {
    let mut b = PatchBuilder::new();
    b.fhdr(b"DIFF", 1).target_info(WIN32);
    build(&mut b);
    b.eof();
    b.bytes()
}

#[test]
fn add_file_writes_a_stored_block() {
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 4, "data.bin", &block_stored(b"WXYZ"));
    });
    let sink = apply_to_mem(&patch).expect("apply");
    assert_eq!(sink.get("data.bin"), Some(&b"WXYZ"[..]));
}

#[test]
fn add_file_decodes_a_deflate_block() {
    let plain = b"the quick brown fox jumps over the lazy dog".repeat(8);
    let patch = boot_patch(|b| {
        b.file_op(
            b'A',
            0,
            plain.len() as i64,
            "text.dat",
            &block_deflate(&plain),
        );
    });
    let sink = apply_to_mem(&patch).expect("apply");
    assert_eq!(sink.get("text.dat"), Some(&plain[..]));
}

#[test]
fn add_file_streams_multiple_blocks_back_to_back() {
    let mut blocks = block_stored(b"HEAD");
    blocks.extend_from_slice(&block_deflate(&b"BODY".repeat(20)));
    let mut expected = b"HEAD".to_vec();
    expected.extend_from_slice(&b"BODY".repeat(20));
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, expected.len() as i64, "multi.dat", &blocks);
    });
    let sink = apply_to_mem(&patch).expect("apply");
    assert_eq!(sink.get("multi.dat"), Some(&expected[..]));
}

#[test]
fn a_continuation_appends_without_truncating() {
    // Two AddFile commands to one file: offset 0 (fresh) then offset 4 (continuation).
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 4, "big.dat", &block_stored(b"HEAD"))
            .file_op(b'A', 4, 4, "big.dat", &block_stored(b"TAIL"));
    });
    let sink = apply_to_mem(&patch).expect("apply");
    assert_eq!(sink.get("big.dat"), Some(&b"HEADTAIL"[..]));
}

#[test]
fn an_offset_zero_add_truncates_the_previous_content() {
    // A second offset-0 AddFile replaces the file wholesale (shorter new content, no stale tail).
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 8, "over.dat", &block_stored(b"OLDLONG!"))
            .file_op(b'A', 0, 3, "over.dat", &block_stored(b"NEW"));
    });
    let sink = apply_to_mem(&patch).expect("apply");
    assert_eq!(sink.get("over.dat"), Some(&b"NEW"[..]));
}

#[test]
fn delete_file_removes_the_target() {
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 2, "gone.dat", &block_stored(b"hi"))
            .file_op(b'D', 0, 0, "gone.dat", &[]);
    });
    let sink = apply_to_mem(&patch).expect("apply");
    assert_eq!(sink.get("gone.dat"), None);
}

#[test]
fn a_non_win32_platform_is_refused() {
    let mut b = PatchBuilder::new();
    b.fhdr(b"DIFF", 1).target_info(PS3).eof();
    assert!(matches!(
        apply_to_mem(&b.bytes()),
        Err(Error::Unsupported { .. })
    ));
}

#[test]
fn an_escaping_path_is_rejected() {
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 4, "../escape.bin", &block_stored(b"evil"));
    });
    assert!(matches!(
        apply_to_mem(&patch),
        Err(Error::PathEscape { .. })
    ));
}

#[test]
fn cancellation_between_commands_aborts() {
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 4, "data.bin", &block_stored(b"WXYZ"));
    });
    let cancel = AtomicBool::new(true);
    let opts = ApplyOptions {
        cancel: Some(&cancel),
        ..Default::default()
    };
    let mut reader = PatchReader::open(&patch[..]).expect("open");
    let mut sink = InMemorySink::default();
    assert!(matches!(
        apply(&mut reader, &mut sink, &opts),
        Err(Error::Cancelled)
    ));
    assert!(
        sink.get("data.bin").is_none(),
        "nothing written after cancel"
    );
}

#[test]
fn progress_reports_the_bytes_written() {
    let plain = b"payload-bytes".repeat(4);
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, plain.len() as i64, "p.dat", &block_deflate(&plain));
    });
    let (tx, rx) = mpsc::channel::<ApplyProgress>();
    let opts = ApplyOptions {
        progress: Some(&tx),
        ..Default::default()
    };
    let mut reader = PatchReader::open(&patch[..]).expect("open");
    let mut sink = InMemorySink::default();
    apply(&mut reader, &mut sink, &opts).expect("apply");
    // Frames are sent synchronously during apply, so they are all buffered by the time it returns.
    let frames: Vec<_> = rx.try_iter().collect();
    let last = frames.last().expect("at least one progress frame");
    assert_eq!(last.bytes_done, plain.len() as u64);
}

#[test]
fn the_effect_trace_is_deterministic() {
    // Stored blocks keep the trace deterministic (a DEFLATE block's compressed length is
    // encoder-dependent). The deflate write path itself is covered by the content tests above.
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 4, "a.dat", &block_stored(b"AAAA"))
            .file_op(b'A', 0, 6, "b.dat", &block_stored(b"BBBBBB"))
            .file_op(b'D', 0, 0, "old.dat", &[]);
    });
    let mut reader = PatchReader::open(&patch[..]).expect("open");
    let mut trace = TraceSink::default();
    apply(&mut reader, &mut trace, &ApplyOptions::default()).expect("apply");
    assert_eq!(
        trace.calls,
        vec![
            "truncate a.dat len=0",
            "write raw a.dat off=0 len=4",
            "truncate b.dat len=0",
            "write raw b.dat off=0 len=6",
            "remove old.dat",
        ]
    );
}

#[test]
fn scan_crc_accepts_a_clean_patch_and_rejects_a_corrupt_one() {
    let patch = boot_patch(|b| {
        b.file_op(b'A', 0, 4, "data.bin", &block_stored(b"WXYZ"));
    });

    let mut reader = PatchReader::open(&patch[..]).expect("open");
    scan_crc(&mut reader).expect("clean scan");

    // Flip a byte inside the first chunk's payload: the stored CRC no longer matches.
    let mut corrupt = patch.clone();
    corrupt[20] ^= 0xFF;
    let mut reader = PatchReader::open(&corrupt[..]).expect("open");
    assert!(matches!(
        scan_crc(&mut reader),
        Err(Error::ChunkCrcMismatch { .. })
    ));
}
