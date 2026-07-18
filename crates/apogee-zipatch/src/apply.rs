//! The apply interpreter: one pass over the chunk stream that turns each command into typed
//! [`PatchSink`] calls. The sink decides what a call *does* (write to disk, index, trace), so apply
//! and index cannot disagree: they are the same execution over the same stream.
//!
//! This is the boot profile. Boot patches use `FHDR`/`APLY`/`SQPK T`/`SQPK X`/`SQPK F`(`A`/`D`)/`EOF_`,
//! so those are wired end to end; the directory and remaining SQPK commands are dispatched to the
//! sink but their disk semantics (empty blocks, header writes, add-data) land in a later phase.
//!
//! `SQPK F:A` (add-file) carries a stream of SqPack blocks. The interpreter *frames* that stream with
//! the shared codec's header parser to find each block's boundary and write offset, then hands one
//! [`DataSource`] per block to the sink: [`DataSource::Raw`] for a stored block, [`DataSource::Deflate`]
//! for a compressed one. Decoding a compressed payload is the sink's job, through the same shared
//! codec, so the writer and the eventual index reader cannot drift.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

use apogee_sqpack::codec;

use crate::chunk::{Chunk, FileOp, FileOperation, Platform, Sqpk};
use crate::error::{Error, Result};
use crate::parse::PatchReader;
use crate::seam::{DataSource, KeepFilter, PatchSink, SafePath, TargetPath};

/// One progress frame emitted between commands. Clockless and advisory: a closed or absent receiver
/// is not an error. `total` is `None` for boot patches, whose `FHDR` carries no command counts.
#[derive(Debug, Clone)]
pub struct ApplyProgress {
    /// Payload bytes written to sinks so far.
    pub bytes_done: u64,
    /// The expected total, when the patch declares it.
    pub total: Option<u64>,
}

/// How an [`apply`] run reports and cancels. Progress is an owned channel (the caller drains it, e.g.
/// re-emitting on the patcher's own stream); cancellation is a single flag checked between commands.
#[derive(Default)]
pub struct ApplyOptions<'a> {
    /// A channel the interpreter sends [`ApplyProgress`] frames to, if any.
    pub progress: Option<&'a Sender<ApplyProgress>>,
    /// A flag polled between commands; set it to abort with [`Error::Cancelled`]. Apply is
    /// re-runnable (writes are positioned, not appended), so a cancelled run is safe to retry.
    pub cancel: Option<&'a AtomicBool>,
}

/// Apply `reader`'s patch to `sink`.
///
/// The reader carries the CRC posture: open it with `.verify_crc(true)` for boot patches (the chunk
/// CRC is their only integrity check). Cancellation is honored between commands.
///
/// # Errors
/// Any parse fault from `reader`, a [`Error::PathEscape`]/[`Error::LimitExceeded`] from confinement, a
/// sink [`Error::Io`], a block-decode fault, [`Error::Unsupported`] for a command outside the boot
/// profile, or [`Error::Cancelled`].
pub fn apply<R: Read, S: PatchSink>(
    reader: &mut PatchReader<R>,
    sink: &mut S,
    opts: &ApplyOptions<'_>,
) -> Result<()> {
    let mut bytes_done = 0u64;
    while let Some(chunk) = reader.next_chunk()? {
        if opts.cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(Error::Cancelled);
        }
        match chunk {
            // Metadata: the command counts drive progress totals, but boot's v2 header carries none.
            Chunk::FileHeader(_) | Chunk::ApplyOption(_) | Chunk::ApplyFreeSpace(_) => {}
            Chunk::AddDirectory(d) => sink.make_dir_tree(&SafePath::confine(&d.path)?)?,
            Chunk::DeleteDirectory(d) => sink.remove_dir(&SafePath::confine(&d.path)?)?,
            Chunk::Sqpk(sqpk) => bytes_done += apply_sqpk(sqpk, sink)?,
            Chunk::EndOfFile => break,
            Chunk::Padding => {}
        }
        emit(
            opts.progress,
            ApplyProgress {
                bytes_done,
                total: None,
            },
        );
    }
    Ok(())
}

/// Scan a patch to `EOF_`, verifying every chunk CRC, without applying anything. This is how a boot
/// patch (which has no block-SHA1 list) earns admission: the chunk CRC is its integrity proof. Open
/// the reader with `.verify_crc(true)` before calling.
///
/// # Errors
/// The first parse or CRC fault; carries the patch-file offset.
pub fn scan_crc<R: Read>(reader: &mut PatchReader<R>) -> Result<()> {
    while reader.next_chunk()?.is_some() {}
    Ok(())
}

/// Dispatch one SQPK command, returning the payload bytes it wrote (for progress).
fn apply_sqpk<S: PatchSink>(sqpk: Sqpk<'_>, sink: &mut S) -> Result<u64> {
    match sqpk {
        // Sets the platform for path resolution. The launcher only installs Win32; console targets
        // parse but are refused here rather than mis-applied.
        Sqpk::TargetInfo(t) if t.platform != Platform::Win32 => Err(Error::Unsupported {
            what: "non-Win32 target platform",
        }),
        Sqpk::TargetInfo(_) | Sqpk::PatchInfo(_) => Ok(0),
        Sqpk::File(f) => apply_file_op(f, sink),
        // A NOP on modern patchers: index files are rewritten wholesale via H/F.
        Sqpk::Index(_) => Ok(0),
        // Present in game/expansion patches, not boot; their disk semantics land in a later phase.
        Sqpk::AddData(_) => Err(Error::Unsupported {
            what: "SQPK A (add-data) apply",
        }),
        Sqpk::DeleteData(_) => Err(Error::Unsupported {
            what: "SQPK D (delete-data) apply",
        }),
        Sqpk::ExpandData(_) => Err(Error::Unsupported {
            what: "SQPK E (expand-data) apply",
        }),
        Sqpk::Header(_) => Err(Error::Unsupported {
            what: "SQPK H (header) apply",
        }),
    }
}

/// Dispatch one `SQPK F` file operation to the sink.
fn apply_file_op<S: PatchSink>(f: FileOp<'_>, sink: &mut S) -> Result<u64> {
    match f.operation {
        FileOperation::AddFile => apply_add_file(&f, sink),
        FileOperation::DeleteFile => {
            sink.remove_file(&TargetPath::confine(&f.path)?)?;
            Ok(0)
        }
        FileOperation::RemoveAll => {
            sink.remove_expansion(f.expansion_id, &KeepFilter::default())?;
            Ok(0)
        }
        FileOperation::MakeDirTree => {
            sink.make_dir_tree(&SafePath::confine(&f.path)?)?;
            Ok(0)
        }
        FileOperation::Other(_) => Err(Error::Unsupported {
            what: "unknown SQPK F operation",
        }),
    }
}

/// Frame the `F:A` block stream and hand one write per block to the sink.
///
/// XL's contract: a fresh file (offset 0) is truncated first, then the decoded blocks are written
/// sequentially from `file_offset`; a continuation (offset > 0) appends without truncating. Each
/// block advances the write offset by its decompressed size.
fn apply_add_file<S: PatchSink>(f: &FileOp<'_>, sink: &mut S) -> Result<u64> {
    let target = TargetPath::confine(&f.path)?;
    let mut write_off = u64::try_from(f.file_offset).map_err(|_| Error::Corrupt {
        offset: f.blocks_off,
        detail: "negative add-file offset",
    })?;
    if write_off == 0 {
        sink.truncate(&target, 0)?;
    }

    let mut written = 0u64;
    let mut rest = f.blocks;
    let mut pos = f.blocks_off;
    while !rest.is_empty() {
        // Frame one block from its 16-byte header (payload size + stored/compressed), no decode.
        let header_slice = rest.get(..16).ok_or_else(|| Error::Truncated {
            offset: pos,
            needed: (16 - rest.len()) as u64,
        })?;
        let header_bytes = <&[u8; 16]>::try_from(header_slice).map_err(|_| Error::Corrupt {
            offset: pos,
            detail: "block header",
        })?;
        let header =
            codec::parse_header(header_bytes).map_err(|e| Error::from_block(e, pos, 0, 0))?;
        let payload_len = if header.is_stored() {
            header.decompressed_size
        } else {
            header.compressed_size
        };
        let block_len = codec::padded_block_len(payload_len).ok_or(Error::Corrupt {
            offset: pos,
            detail: "block length overflow",
        })? as usize;
        if rest.len() < block_len {
            return Err(Error::Truncated {
                offset: pos,
                needed: (block_len - rest.len()) as u64,
            });
        }
        let payload = &rest[16..16 + payload_len as usize];
        let payload_off = pos + 16;
        if header.is_stored() {
            sink.write(
                &target,
                write_off,
                DataSource::Raw {
                    patch_off: payload_off,
                    bytes: payload,
                },
            )?;
        } else {
            sink.write(
                &target,
                write_off,
                DataSource::Deflate {
                    patch_off: payload_off,
                    compressed_len: header.compressed_size,
                    decompressed_len: header.decompressed_size,
                    bytes: payload,
                },
            )?;
        }

        write_off += u64::from(header.decompressed_size);
        written += u64::from(header.decompressed_size);
        pos += block_len as u64;
        rest = &rest[block_len..];
    }
    Ok(written)
}

/// Send a progress frame, ignoring a closed or absent receiver (progress is advisory).
fn emit(tx: Option<&Sender<ApplyProgress>>, event: ApplyProgress) {
    if let Some(tx) = tx {
        let _ = tx.send(event);
    }
}
