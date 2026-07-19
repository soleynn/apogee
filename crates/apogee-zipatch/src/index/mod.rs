//! The block index: build a per-version map of every target byte range to the source bytes that
//! produce it, serialize it as an `.apzi` file, verify a live install against it, and reconstruct the
//! tree from it. Building rides the same interpreter the applier does ([`crate::apply`]) with an
//! [`sink::IndexSink`] in place of the disk sink, so the index and an apply cannot disagree.
//!
//! Build is two passes. The first interprets each patch in chain order and records a provenance-only
//! tiling per target file ([`model::TargetFile`]); the second reads the source patches back to
//! compute each part's CRC32 (the tiling's splits leave CRCs invalid until then, and a compressed
//! block can only be summed after inflating, so the CRC is deferred to a pass with source access).

mod format;
mod model;
mod reconstruct;
mod repair;
mod sink;
mod verify;

use std::io::{Read, Seek, SeekFrom};

use apogee_sqpack::codec;

use crate::apply::{ApplyOptions, apply};
use crate::chunk::Platform;
use crate::error::{Error, Op, Result};
use crate::parse::PatchReader;

use model::{Source, SourcePatch, TargetFile};
use reconstruct::MAX_BLOCK_DECOMPRESSED;
use sink::IndexSink;

pub use model::Index;
pub use repair::{RepairOutcome, SourceRef};
pub use verify::{PartRef, SizeMismatch, StrayFile, VerifyOptions, VerifyReport};

/// Build a block index from a patch chain.
///
/// `patches` are `(name, reader)` pairs in apply order; each reader must be seekable (the build reads
/// it once to interpret, then again to sum each part). `repo_version` labels the version the index
/// describes. Reconstruction and repair later hand back sources in this same order.
///
/// # Errors
/// Any parse or apply fault from a source patch, [`Error::Io`] on a read, or a block-decode fault
/// while summing a compressed part.
pub fn build<R: Read + Seek>(
    mut patches: Vec<(String, R)>,
    platform: Platform,
    repo_version: impl Into<String>,
) -> Result<Index> {
    // Pass 1: interpret each patch, accumulating the per-file tiling with source provenance.
    let mut sink = IndexSink::new();
    let mut sources = Vec::new();
    for (idx, (name, reader)) in patches.iter_mut().enumerate() {
        let idx = u16::try_from(idx).map_err(|_| Error::Corrupt {
            offset: 0,
            detail: "too many source patches for one index",
        })?;
        sink.set_source(idx);
        let mut r = PatchReader::open(&mut *reader)?.verify_crc(true);
        apply(&mut r, &mut sink, &ApplyOptions::default())?;
        let expected_len = reader.seek(SeekFrom::End(0)).map_err(|e| io(e, Op::Read))?;
        sources.push(SourcePatch {
            name: name.clone(),
            expected_len,
        });
    }
    let targets: Vec<TargetFile> = sink.into_targets().into_values().collect();
    let mut index = Index {
        repo_version: repo_version.into(),
        platform,
        sources,
        targets,
    };

    // Pass 2: sum every source-backed part from the patches (the sentinels are checked structurally).
    let mut readers: Vec<R> = patches.into_iter().map(|(_, r)| r).collect();
    let limits = codec::Limits {
        max_decompressed: MAX_BLOCK_DECOMPRESSED,
    };
    for target in &mut index.targets {
        for part in &mut target.parts {
            if matches!(part.source, Source::Patch { .. }) {
                let bytes = reconstruct::materialize_patch(part, &mut readers, &limits)?;
                part.crc32 = crc32fast::hash(&bytes);
                part.crc_valid = true;
            }
        }
    }
    Ok(index)
}

fn io(source: std::io::Error, during: Op) -> Error {
    Error::Io {
        source,
        target: None,
        during,
    }
}
