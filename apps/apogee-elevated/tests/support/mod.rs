//! Shared scaffolding for the worker tests.
//!
//! Everything here returns a `Result`: the unwrap relaxation these integration targets carry covers
//! test bodies, not the helpers they call.
// Each integration target compiles this module separately, so whatever a given one does not reach is
// dead in that target's eyes. The alternative is a copy of these helpers per target, which is the
// duplication the module exists to remove.
#![allow(
    dead_code,
    reason = "shared across integration targets, compiled once per target"
)]

use std::error::Error;
use std::path::Path;
use std::process::Stdio;

use apogee_elevate::{Admission, Session, StagedOp, StagedWrite};
use apogee_zipatch::fixtures::{self, PatchBuilder, WIN32};
use sha1::{Digest, Sha1};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// The block width the synthetic patchlist digests are taken over, small enough that a patch spans
/// many blocks.
pub const BLOCK_SIZE: usize = 64;

/// A worker running as a plain child, with the process handle kept separate from the session so a
/// test can kill one while driving the other.
pub struct Harness {
    pub child: Child,
    pub session: Session<ChildStdout, ChildStdin>,
}

/// Start the worker binary under test on its own standard streams.
pub async fn start() -> Result<Harness, Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_apogee-elevated"))
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let (Some(stdout), Some(stdin)) = (child.stdout.take(), child.stdin.take()) else {
        return Err("the worker's standard streams were not piped".into());
    };
    let session = Session::open(stdout, stdin).await?;
    Ok(Harness { child, session })
}

/// Write `bytes` to `dir/name` and hand back the path.
pub fn place(dir: &Path, name: &str, bytes: &[u8]) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let path = dir.join(name);
    std::fs::write(&path, bytes)?;
    Ok(path)
}

/// The chunk-CRC admission for `bytes`, carrying the whole-file digest the launcher takes when its
/// own scan admits a boot patch.
pub fn chunk_crc(bytes: &[u8]) -> Admission {
    Admission::ChunkCrc {
        content: *blake3::hash(bytes).as_bytes(),
    }
}

/// Per-block lowercase-hex SHA1 over `bytes`, the shape a game patchlist publishes.
pub fn block_sha1_hex(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(BLOCK_SIZE)
        .map(|block| {
            Sha1::digest(block)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .collect()
}

/// The per-block SHA1 admission for `bytes`.
pub fn block_sha1(bytes: &[u8]) -> Admission {
    Admission::BlockSha1 {
        block_size: BLOCK_SIZE as u32,
        hashes: block_sha1_hex(bytes),
    }
}

/// A staging file holding `spans` back to back, plus the [`StagedOp::Bytes`] that reads each one
/// back out: `spans[i]` lands at `targets[i]` in the bound tree.
///
/// The digests are taken here, over the bytes as written, which is what the parent does: it measures
/// what it staged and the worker measures what it reads.
pub fn stage(
    path: &Path,
    spans: &[(&str, u64, Vec<u8>)],
) -> Result<Vec<StagedWrite>, Box<dyn Error>> {
    let mut staged = Vec::new();
    let mut writes = Vec::new();
    for (target, off, bytes) in spans {
        writes.push(StagedWrite {
            path: (*target).to_owned(),
            op: StagedOp::Bytes {
                off: *off,
                staged_off: staged.len() as u64,
                len: u32::try_from(bytes.len())?,
                digest: *blake3::hash(bytes).as_bytes(),
            },
        });
        staged.extend_from_slice(bytes);
    }
    std::fs::write(path, &staged)?;
    Ok(writes)
}

/// A patch that writes `chunks` runs of `chunk_len` identical bytes into one file.
///
/// Deflated, so the patch on disk stays small while the apply writes real bytes: the tests that kill
/// the worker part way through need a run long enough that the first progress frame lands nowhere
/// near the end, and paying for that in patch-file size would make the fixture unwieldy.
pub fn wide_patch(name: &str, chunks: usize, chunk_len: usize) -> Vec<u8> {
    let mut builder = PatchBuilder::new();
    builder.fhdr(b"DIFF", 0).target_info(WIN32);
    for chunk in 0..chunks {
        let payload = vec![filler(chunk); chunk_len];
        let blocks = fixtures::block_deflate(&payload);
        let offset = (chunk * chunk_len) as i64;
        let declared = if chunk == 0 {
            (chunks * chunk_len) as i64
        } else {
            0
        };
        builder.file_op(b'A', offset, declared, name, &blocks);
    }
    builder.eof();
    builder.bytes()
}

/// The byte a given run of [`wide_patch`] is filled with, so a test can rebuild what it expects.
pub fn filler(chunk: usize) -> u8 {
    (chunk % 251) as u8
}

/// What [`wide_patch`] should leave on disk.
pub fn wide_expected(chunks: usize, chunk_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunks * chunk_len);
    for chunk in 0..chunks {
        out.extend(std::iter::repeat_n(filler(chunk), chunk_len));
    }
    out
}
