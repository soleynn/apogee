//! Turning index parts back into bytes. The build's CRC pass and the full-tree reconstructor share
//! one per-part materializer: a stored part is copied from its patch, a compressed part is inflated
//! (the whole block, then sliced from `decoded_from`) through the shared SqPack codec, and the
//! zeros/empty-block sentinels are generated locally. The reconstructor writes a fresh tree that is
//! byte-identical to what the applier would have produced, which is the `apply ≡ reconstruct` gate;
//! it also underlies the repair phase, where only broken ranges are pulled.
//!
//! Large zero and empty-block runs are never materialized: the target file is sized once with a
//! sparse `set_len`, then only the non-zero bytes (patch data and the 24-byte empty-block header) are
//! written, so an `E` expand of many gigabytes costs a handful of writes, exactly like the applier.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use apogee_sqpack::codec;

use crate::datfile;
use crate::error::{Error, Op, Result};
use crate::index::model::{Index, Part, Source, TargetFile};

/// The decode cap for one compressed block, matching the apply engine's bound.
pub(crate) const MAX_BLOCK_DECOMPRESSED: u32 = 16 << 20;

impl Index {
    /// Reconstruct the whole tree under `root` from the index, pulling source bytes from `sources`
    /// (the same patches, in the same chain order, that [`crate::index::build`] consumed).
    ///
    /// # Errors
    /// [`Error::Io`] on a filesystem fault, a block-decode fault, or [`Error::Corrupt`] if the index
    /// references a source patch or offset that is not there.
    pub fn reconstruct<R: Read + Seek>(&self, root: &Path, sources: &mut [R]) -> Result<()> {
        let limits = codec::Limits {
            max_decompressed: MAX_BLOCK_DECOMPRESSED,
        };
        for target in &self.targets {
            reconstruct_target(target, root, sources, &limits)?;
        }
        Ok(())
    }
}

/// Write one target file: size it sparsely, then lay down each part's non-zero bytes.
fn reconstruct_target<R: Read + Seek>(
    target: &TargetFile,
    root: &Path,
    sources: &mut [R],
    limits: &codec::Limits,
) -> Result<()> {
    let abs = root.join(&target.path);
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::io(e, Op::MakeDir))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&abs)
        .map_err(|e| Error::io(e, Op::Open))?;
    file.set_len(target.final_len())
        .map_err(|e| Error::io(e, Op::Truncate))?;

    for part in &target.parts {
        match part.source {
            Source::Patch { .. } => {
                let bytes = materialize_patch(part, sources, limits)?;
                write_at(&mut file, part.target_off, &bytes)?;
            }
            Source::EmptyBlock {
                block_count,
                decoded_from,
            } => {
                if let Some(hdr) =
                    empty_block_header_slice(block_count, decoded_from, part.target_len)
                {
                    write_at(&mut file, part.target_off, &hdr)?;
                }
            }
            // The file was already sized sparsely; a zero run needs no write.
            Source::Zeros => {}
            Source::Unavailable => {
                return Err(Error::Corrupt {
                    offset: part.target_off,
                    detail: "reconstruct hit an unavailable index part",
                });
            }
        }
    }
    Ok(())
}

/// The final bytes of a stored/compressed patch part.
///
/// # Errors
/// [`Error::Corrupt`] if the source index or a decoded slice is out of range, a block-decode fault,
/// or [`Error::Io`]/[`Error::Truncated`] on a source read.
pub(crate) fn materialize_patch<R: Read + Seek>(
    part: &Part,
    sources: &mut [R],
    limits: &codec::Limits,
) -> Result<Vec<u8>> {
    let Source::Patch {
        idx,
        off,
        deflated,
        deflated_len,
        block_dlen,
        decoded_from,
    } = part.source
    else {
        return Err(Error::Corrupt {
            offset: part.target_off,
            detail: "materialize called on a non-patch part",
        });
    };

    if !deflated {
        return read_exact_at(sources, idx, off, part.target_len as usize);
    }

    let compressed = read_exact_at(sources, idx, off, deflated_len as usize)?;
    let mut whole = Vec::new();
    codec::inflate(&compressed, &mut whole, block_dlen, limits)
        .map_err(|e| Error::from_block(e, off, block_dlen, limits.max_decompressed))?;
    let start = decoded_from as usize;
    let end = start
        .checked_add(part.target_len as usize)
        .ok_or(Error::Corrupt {
            offset: part.target_off,
            detail: "index part decoded slice overflow",
        })?;
    if whole.len() < end {
        return Err(Error::Corrupt {
            offset: part.target_off,
            detail: "index part decoded slice out of range",
        });
    }
    // Keep only the requested window in place: the common unsplit part (`start == 0`, `end == len`)
    // returns the whole block with no extra allocation or copy.
    whole.truncate(end);
    whole.drain(..start);
    Ok(whole)
}

/// The empty-block header bytes that overlap `[decoded_from, decoded_from + len)`, written at the
/// part's start; `None` when the part lies wholly past the 24-byte header (an all-zero remainder,
/// already covered by the sparse `set_len`).
pub(crate) fn empty_block_header_slice(
    block_count: u32,
    decoded_from: u64,
    len: u64,
) -> Option<Vec<u8>> {
    let header = datfile::empty_block_header(block_count);
    let header_len = header.len() as u64;
    if decoded_from >= header_len || len == 0 {
        return None;
    }
    // `len` is a target length from a possibly-hostile index; saturate rather than overflow before
    // clamping to the 24-byte header (`decoded_from` is already `< header_len` here).
    let end = decoded_from.saturating_add(len).min(header_len);
    Some(header[decoded_from as usize..end as usize].to_vec())
}

/// Read exactly `len` bytes from source patch `idx` at byte offset `off`.
fn read_exact_at<R: Read + Seek>(
    sources: &mut [R],
    idx: u16,
    off: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let reader = sources.get_mut(idx as usize).ok_or(Error::Corrupt {
        offset: off,
        detail: "index references an out-of-range source patch",
    })?;
    reader
        .seek(SeekFrom::Start(off))
        .map_err(|e| Error::io(e, Op::Read))?;
    // Grow the buffer only as bytes actually arrive, so an oversized length from a hostile index
    // reads (at most) the real source rather than pre-allocating the claimed size.
    let mut buf = Vec::new();
    reader
        .take(len as u64)
        .read_to_end(&mut buf)
        .map_err(|e| Error::io(e, Op::Read))?;
    if buf.len() != len {
        return Err(Error::Truncated {
            offset: off,
            needed: (len - buf.len()) as u64,
        });
    }
    Ok(buf)
}

/// Write `buf` at absolute offset `off`.
pub(crate) fn write_at(file: &mut File, off: u64, buf: &[u8]) -> Result<()> {
    file.seek(SeekFrom::Start(off))
        .map_err(|e| Error::io(e, Op::Write))?;
    file.write_all(buf).map_err(|e| Error::io(e, Op::Write))
}
