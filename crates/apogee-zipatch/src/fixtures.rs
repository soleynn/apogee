//! Synthetic ZiPatch builders for tests, behind the `test-fixtures` feature.
//!
//! One patch-format authority for every test that needs real `.patch` bytes: this crate's own
//! apply/index/repair integration tests and, across the workspace, `apogee-fetch`'s
//! repair-over-HTTP e2e (which serves these bytes through a range source). Keeping the builders here
//! rather than in each crate's `tests/` means the framing has a single owner and cannot drift from
//! the parser it feeds. Every byte-order conversion routes through the crate's [`bytes`](crate::bytes)
//! home, so the endianness audit gate covers the fixtures too.
//!
//! The builders operate on in-memory buffers that cannot fail in practice, so they assert their
//! construction invariants rather than threading a `Result` through every chained call.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Cursor, Write};
use std::path::Path;

use crate::bytes::{
    write_i16_be, write_i64_be, write_u16_be, write_u32_be, write_u32_le, write_u64_le,
};
use crate::error::Result;
use crate::{ApplyOptions, DiskSink, Index, MAGIC, PatchReader, Platform, apply, build_index};

/// Builds ZiPatch bytes chunk by chunk, framing each `[u32be size][4-char type][payload][u32be crc]`
/// exactly as the container does; SQPK chunks get the `innerSize`/command prefix.
#[derive(Default)]
pub struct PatchBuilder {
    body: Vec<u8>,
}

impl PatchBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn chunk(&mut self, fourcc: &[u8; 4], payload: &[u8]) -> &mut Self {
        self.body
            .extend_from_slice(&write_u32_be(payload.len() as u32));
        self.body.extend_from_slice(fourcc);
        self.body.extend_from_slice(payload);
        let mut crc_input = fourcc.to_vec();
        crc_input.extend_from_slice(payload);
        let crc = crc32fast::hash(&crc_input);
        self.body.extend_from_slice(&write_u32_be(crc));
        self
    }

    /// Frame a SQPK chunk: `innerSize` (== payload len) + 1-char command + command payload.
    pub fn sqpk(&mut self, command: u8, cmd_payload: &[u8]) -> &mut Self {
        let inner_len = (4 + 1 + cmd_payload.len()) as u32;
        let mut payload = Vec::new();
        payload.extend_from_slice(&write_u32_be(inner_len));
        payload.push(command);
        payload.extend_from_slice(cmd_payload);
        self.chunk(b"SQPK", &payload)
    }

    pub fn fhdr(&mut self, patch_type: &[u8; 4], entry_files: u32) -> &mut Self {
        let mut v = Vec::new();
        v.extend_from_slice(&write_u32_le(0x0002_0000)); // version dword (LE): v2
        v.extend_from_slice(patch_type);
        v.extend_from_slice(&write_u32_be(entry_files));
        v.extend_from_slice(&[0u8; 8]); // v2 trailing zeros
        self.chunk(b"FHDR", &v)
    }

    pub fn target_info(&mut self, platform: u16) -> &mut Self {
        let mut v = Vec::new();
        v.extend_from_slice(&[0, 0, 0]); // reserved / alignment
        v.extend_from_slice(&write_u16_be(platform));
        v.extend_from_slice(&write_i16_be(-1)); // region: global
        v.extend_from_slice(&write_u16_be(0)); // isDebug
        v.extend_from_slice(&write_u16_be(0)); // version
        v.extend_from_slice(&write_u64_le(0)); // deletedDataSize (LE)
        v.extend_from_slice(&write_u64_le(0)); // seekCount (LE)
        self.sqpk(b'T', &v)
    }

    /// A `SQPK F` file op. `blocks` is the raw block stream (only meaningful for `A`).
    pub fn file_op(
        &mut self,
        op: u8,
        file_offset: i64,
        file_size: i64,
        path: &str,
        blocks: &[u8],
    ) -> &mut Self {
        let mut v = Vec::new();
        v.push(op);
        v.extend_from_slice(&[0, 0]); // alignment
        v.extend_from_slice(&write_i64_be(file_offset));
        v.extend_from_slice(&write_i64_be(file_size));
        v.extend_from_slice(&write_u32_be(path.len() as u32));
        v.extend_from_slice(&write_u16_be(0)); // expansionId
        v.extend_from_slice(&[0, 0]); // padding
        v.extend_from_slice(path.as_bytes());
        v.extend_from_slice(blocks);
        self.sqpk(b'F', &v)
    }

    /// A `SQPK A` (AddData) command. `block_offset` and `block_delete` are byte counts (128-aligned),
    /// and `data`'s length must be 128-aligned; the wire stores each `>> 7`.
    pub fn add_data(
        &mut self,
        target: (u16, u16, u32),
        block_offset: u64,
        data: &[u8],
        block_delete: u64,
    ) -> &mut Self {
        assert_eq!(block_offset % 128, 0, "block offset must be 128-aligned");
        assert_eq!(data.len() % 128, 0, "add-data length must be 128-aligned");
        assert_eq!(block_delete % 128, 0, "wipe length must be 128-aligned");
        let mut v = Vec::new();
        v.extend_from_slice(&[0, 0, 0]); // alignment
        v.extend_from_slice(&target_bytes(target));
        v.extend_from_slice(&write_u32_be((block_offset >> 7) as u32));
        v.extend_from_slice(&write_u32_be((data.len() as u64 >> 7) as u32));
        v.extend_from_slice(&write_u32_be((block_delete >> 7) as u32));
        v.extend_from_slice(data);
        self.sqpk(b'A', &v)
    }

    /// A `SQPK D`/`E` (Delete/Expand) command. `cmd` is `b'D'` or `b'E'`; `block_offset` is a
    /// 128-aligned byte count stored `>> 7`, `block_count` is the raw (unshifted) 128-byte block span.
    pub fn empty_block(
        &mut self,
        cmd: u8,
        target: (u16, u16, u32),
        block_offset: u64,
        block_count: u32,
    ) -> &mut Self {
        assert_eq!(block_offset % 128, 0, "block offset must be 128-aligned");
        let mut v = Vec::new();
        v.extend_from_slice(&[0, 0, 0]); // alignment
        v.extend_from_slice(&target_bytes(target));
        v.extend_from_slice(&write_u32_be((block_offset >> 7) as u32));
        v.extend_from_slice(&write_u32_be(block_count)); // NOT shifted
        v.extend_from_slice(&write_u32_be(0)); // reserved
        self.sqpk(cmd, &v)
    }

    /// A `SQPK H` (Header) command. `file_kind` is `b'D'` (dat) or `b'I'` (index); `header_kind` is
    /// `b'V'`/`b'I'`/`b'D'`; `blob` must be exactly 1024 bytes.
    pub fn header(
        &mut self,
        file_kind: u8,
        header_kind: u8,
        target: (u16, u16, u32),
        blob: &[u8],
    ) -> &mut Self {
        assert_eq!(blob.len(), 1024, "header blob must be 1024 bytes");
        let mut v = Vec::new();
        v.push(file_kind);
        v.push(header_kind);
        v.push(0); // alignment
        v.extend_from_slice(&target_bytes(target));
        v.extend_from_slice(blob);
        self.sqpk(b'H', &v)
    }

    /// A `SQPK F:R` (RemoveAll) command for `expansion_id`. The path field is unused by the apply.
    pub fn removeall(&mut self, expansion_id: u16, path: &str) -> &mut Self {
        let mut v = Vec::new();
        v.push(b'R');
        v.extend_from_slice(&[0, 0]); // alignment
        v.extend_from_slice(&write_i64_be(0)); // fileOffset
        v.extend_from_slice(&write_i64_be(0)); // fileSize
        v.extend_from_slice(&write_u32_be(path.len() as u32));
        v.extend_from_slice(&write_u16_be(expansion_id));
        v.extend_from_slice(&[0, 0]); // padding
        v.extend_from_slice(path.as_bytes());
        self.sqpk(b'F', &v)
    }

    pub fn add_directory(&mut self, path: &str) -> &mut Self {
        self.directory_chunk(b"ADIR", path)
    }

    pub fn delete_directory(&mut self, path: &str) -> &mut Self {
        self.directory_chunk(b"DELD", path)
    }

    /// An `ADIR`/`DELD` chunk: `u32be pathLen` + path bytes.
    fn directory_chunk(&mut self, fourcc: &[u8; 4], path: &str) -> &mut Self {
        let mut v = Vec::new();
        v.extend_from_slice(&write_u32_be(path.len() as u32));
        v.extend_from_slice(path.as_bytes());
        self.chunk(fourcc, &v)
    }

    pub fn eof(&mut self) -> &mut Self {
        self.chunk(b"EOF_", &[])
    }

    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&self.body);
        out
    }
}

/// The 8-byte file-target triple: mainId/subId big-endian u16, fileId big-endian u32.
fn target_bytes((main_id, sub_id, file_id): (u16, u16, u32)) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&write_u16_be(main_id));
    v.extend_from_slice(&write_u16_be(sub_id));
    v.extend_from_slice(&write_u32_be(file_id));
    v
}

/// The 24-byte empty-block header a `D`/`E` command stamps, encoded here independently of the crate
/// so a test asserts against its own copy of the layout. Five little-endian fields: block size 128,
/// two zeros, `blockCount - 1` as a **u64** (so `block_count == 0` wraps to all ones), a trailing zero.
#[must_use]
pub fn empty_block_header(block_count: u32) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0..4].copy_from_slice(&write_u32_le(128));
    out[12..20].copy_from_slice(&write_u64_le(u64::from(block_count).wrapping_sub(1)));
    out
}

/// One SqPack block: a 16-byte LE header (`header_size`, pad, `compressed_size`, `decompressed_size`)
/// then `payload`, padded to a 128-byte boundary.
fn block(compressed_size: u32, decompressed_size: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&write_u32_le(16)); // header_size
    b.extend_from_slice(&write_u32_le(0)); // pad
    b.extend_from_slice(&write_u32_le(compressed_size));
    b.extend_from_slice(&write_u32_le(decompressed_size));
    b.extend_from_slice(payload);
    pad_to_128(b)
}

/// A stored (uncompressed) SqPack block carrying `payload` verbatim.
#[must_use]
pub fn block_stored(payload: &[u8]) -> Vec<u8> {
    block(0x7D00, payload.len() as u32, payload)
}

/// A DEFLATE-compressed SqPack block that decodes to `plain` (raw deflate, no zlib wrapper).
#[must_use]
pub fn block_deflate(plain: &[u8]) -> Vec<u8> {
    let compressed = deflate_raw(plain);
    block(compressed.len() as u32, plain.len() as u32, &compressed)
}

/// A DEFLATE block whose header claims `claimed_decompressed` output bytes (which may differ from the
/// true size), for driving the decode-size cap and size-mismatch paths.
#[must_use]
pub fn block_deflate_claiming(plain: &[u8], claimed_decompressed: u32) -> Vec<u8> {
    let compressed = deflate_raw(plain);
    block(compressed.len() as u32, claimed_decompressed, &compressed)
}

/// A well-framed block whose payload is not valid DEFLATE, so decoding it fails.
#[must_use]
pub fn block_bad_deflate(payload_len: u32, decompressed: u32) -> Vec<u8> {
    block(payload_len, decompressed, &vec![0xFFu8; payload_len as usize])
}

/// A block with an arbitrary (possibly hostile) header, for framing/guard tests.
#[must_use]
pub fn block_raw(compressed_size: u32, decompressed_size: u32, payload: &[u8]) -> Vec<u8> {
    block(compressed_size, decompressed_size, payload)
}

fn pad_to_128(mut v: Vec<u8>) -> Vec<u8> {
    let target = (v.len() + 127) & !127;
    v.resize(target, 0);
    v
}

fn deflate_raw(plain: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(plain).expect("deflate write");
    e.finish().expect("deflate finish")
}

/// A tiny deterministic PRNG (no `rand` dependency) for seeded, reproducible corruption in a repair
/// property loop. Advance `state` and return the next value.
pub fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// ---- Shared boot-chain fixture (the two-patch chain the index integration tests exercise) ----

/// Platform id for the target-info command in the fixtures.
pub const WIN32: u16 = 0;
/// The base-game dat and its file-target triple.
pub const DAT0: (u16, u16, u32) = (0x0a, 0x0000, 0);
/// The confined relative path `DAT0` resolves to.
pub const DAT0_PATH: &str = "sqpack/ffxiv/0a0000.win32.dat0";

/// First patch: seed a dat with an `A` write superseded-and-extended by an `H` header, and add a
/// stored+compressed exe, a small file later deleted, and a compressed dat.
#[must_use]
pub fn patch_a() -> Vec<u8> {
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
#[must_use]
pub fn patch_b() -> Vec<u8> {
    let mut b = PatchBuilder::new();
    b.fhdr(b"DIFF", 0).target_info(WIN32);
    b.add_data(DAT0, 256, &[0x33u8; 128], 0);
    b.empty_block(b'E', DAT0, 1024, 4);
    b.file_op(b'D', 0, 0, "old.txt", &[]);
    b.file_op(b'A', 128, 0, "data.bin", &block_stored(&[0x99u8; 64]));
    b.eof();
    b.bytes()
}

/// The two-patch chain.
#[must_use]
pub fn chain() -> Vec<Vec<u8>> {
    vec![patch_a(), patch_b()]
}

/// Apply a chain under `root`, one fresh sink per patch (as the patcher runs them).
///
/// # Errors
/// Any parse or apply [`Error`](crate::Error) from the underlying [`apply`].
pub fn apply_chain(root: &Path, patches: &[Vec<u8>]) -> Result<()> {
    for patch in patches {
        let mut reader = PatchReader::open(Cursor::new(patch.clone()))?.verify_crc(true);
        let mut sink = DiskSink::new(root)?;
        apply(&mut reader, &mut sink, &ApplyOptions::default())?;
    }
    Ok(())
}

/// Build an index over a chain (each patch a seekable in-memory source).
///
/// # Errors
/// Any parse or index [`Error`](crate::Error) from [`build_index`].
pub fn build_from(patches: &[Vec<u8>]) -> Result<Index> {
    let inputs: Vec<(String, Cursor<Vec<u8>>)> = patches
        .iter()
        .enumerate()
        .map(|(i, p)| (format!("p{i}.patch"), Cursor::new(p.clone())))
        .collect();
    build_index(inputs, Platform::Win32, "test-version")
}
