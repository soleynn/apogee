//! Shared helpers for the apply/index integration tests: the two mock [`PatchSink`]s (an in-memory
//! applier and a call recorder) and two mock [`RangeSource`]s. The synthetic patch/block builders
//! themselves live in the crate's feature-gated [`apogee_zipatch::fixtures`] module (the one
//! patch-format authority, shared with `apogee-fetch`'s repair e2e) and are re-exported here so the
//! test call sites are unchanged.
//!
//! Each test binary pulls in the whole module but uses only part of it, so unused-item warnings are
//! expected and silenced here. The mock sinks operate on in-memory buffers that cannot fail in
//! practice, so they assert rather than thread a `Result` through every call site.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::{Path, PathBuf};

use apogee_zipatch::{
    DataSource, Error, KeepFilter, PatchId, PatchSink, RangeSource, SafePath, TargetPath,
};

pub use apogee_zipatch::fixtures::*;

/// A [`PatchSink`] that reconstructs each file in memory, so a test can assert final contents.
#[derive(Default)]
pub struct InMemorySink {
    pub files: BTreeMap<PathBuf, Vec<u8>>,
}

impl InMemorySink {
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(&PathBuf::from(path)).map(Vec::as_slice)
    }

    fn splice(&mut self, path: PathBuf, off: u64, bytes: &[u8]) {
        let buf = self.files.entry(path).or_default();
        let end = off as usize + bytes.len();
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[off as usize..end].copy_from_slice(bytes);
    }
}

impl PatchSink for InMemorySink {
    fn write(&mut self, target: &TargetPath, off: u64, src: DataSource<'_>) -> Result<(), Error> {
        let path = target.as_path().to_path_buf();
        let bytes = match src {
            DataSource::Raw { bytes, .. } => bytes.to_vec(),
            DataSource::Deflate {
                bytes,
                decompressed_len,
                ..
            } => {
                let mut out = Vec::new();
                let mut dec = flate2::read::DeflateDecoder::new(bytes);
                std::io::copy(&mut dec, &mut out).expect("inflate");
                assert_eq!(
                    out.len(),
                    decompressed_len as usize,
                    "declared decompressed size"
                );
                out
            }
            DataSource::Zeros { len } => vec![0u8; len as usize],
        };
        self.splice(path, off, &bytes);
        Ok(())
    }

    fn write_empty_block(
        &mut self,
        target: &TargetPath,
        off: u64,
        blocks: u32,
    ) -> Result<(), Error> {
        // Faithful to the disk sink: zero the whole run, then stamp the 24-byte header over its start
        // (including the block_count == 0 case, where the wipe is empty but the header still lands).
        let path = target.as_path().to_path_buf();
        let wipe = vec![0u8; (u64::from(blocks) << 7) as usize];
        self.splice(path.clone(), off, &wipe);
        self.splice(path, off, &empty_block_header(blocks));
        Ok(())
    }

    fn truncate(&mut self, target: &TargetPath, len: u64) -> Result<(), Error> {
        self.files
            .entry(target.as_path().to_path_buf())
            .or_default()
            .resize(len as usize, 0);
        Ok(())
    }

    fn remove_file(&mut self, target: &TargetPath) -> Result<(), Error> {
        self.files.remove(target.as_path());
        Ok(())
    }

    fn remove_expansion(&mut self, exp: u16, keep: &KeepFilter) -> Result<(), Error> {
        // Model the reference sweep over the modeled tree: immediate files of sqpack/{xpac} and
        // movie/{xpac}, keeping those the filter spares.
        let folder = if (exp as u8) == 0 {
            "ffxiv".to_owned()
        } else {
            format!("ex{}", exp as u8)
        };
        let dirs = [format!("sqpack/{folder}"), format!("movie/{folder}")];
        self.files.retain(|path, _| {
            let in_sweep = path
                .parent()
                .is_some_and(|p| dirs.iter().any(|d| p == Path::new(d)));
            if !in_sweep {
                return true;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            keep.is_kept(&name)
        });
        Ok(())
    }

    fn make_dir_tree(&mut self, _rel: &SafePath) -> Result<(), Error> {
        Ok(())
    }

    fn remove_dir(&mut self, _rel: &SafePath) -> Result<(), Error> {
        Ok(())
    }
}

/// A [`RangeSource`] over in-memory patch bytes that records what it serves, so a repair test can
/// assert it pulled only the broken ranges. `patches[i]` backs `PatchId(i)`, matching the index's
/// chain order.
pub struct CountingSource {
    patches: Vec<Vec<u8>>,
    pub bytes_served: u64,
    pub ranges: Vec<(u32, Range<u64>)>,
}

impl CountingSource {
    pub fn new(patches: Vec<Vec<u8>>) -> Self {
        Self {
            patches,
            bytes_served: 0,
            ranges: Vec::new(),
        }
    }

    /// Bytes served for a specific patch id.
    pub fn ranges_for(&self, patch: u32) -> usize {
        self.ranges.iter().filter(|(p, _)| *p == patch).count()
    }
}

impl RangeSource for CountingSource {
    fn read_ranges(
        &mut self,
        patch: PatchId,
        ranges: &[Range<u64>],
        out: &mut dyn FnMut(u64, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let data = &self.patches[patch.0 as usize];
        for r in ranges {
            let slice = &data[r.start as usize..r.end as usize];
            self.bytes_served += slice.len() as u64;
            self.ranges.push((patch.0, r.clone()));
            out(r.start, slice)?;
        }
        Ok(())
    }
}

/// A [`RangeSource`] that serves each range from the patch bytes with its first byte flipped, so a
/// stored part decodes cleanly yet fails its CRC — exercising the soft `still_broken` path where a
/// bad fetch must not corrupt the tree.
pub struct TamperSource {
    patches: Vec<Vec<u8>>,
}

impl TamperSource {
    pub fn new(patches: Vec<Vec<u8>>) -> Self {
        Self { patches }
    }
}

impl RangeSource for TamperSource {
    fn read_ranges(
        &mut self,
        patch: PatchId,
        ranges: &[Range<u64>],
        out: &mut dyn FnMut(u64, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let data = &self.patches[patch.0 as usize];
        for r in ranges {
            let mut slice = data[r.start as usize..r.end as usize].to_vec();
            if let Some(b) = slice.first_mut() {
                *b ^= 0xFF;
            }
            out(r.start, &slice)?;
        }
        Ok(())
    }
}

/// A [`PatchSink`] that records each call as a byte-free line, for deterministic effect-trace asserts.
#[derive(Default)]
pub struct TraceSink {
    pub calls: Vec<String>,
}

impl PatchSink for TraceSink {
    fn write(&mut self, target: &TargetPath, off: u64, src: DataSource<'_>) -> Result<(), Error> {
        let path = target.as_path().display();
        let line = match src {
            DataSource::Raw { bytes, .. } => {
                format!("write raw {path} off={off} len={}", bytes.len())
            }
            DataSource::Deflate {
                compressed_len,
                decompressed_len,
                ..
            } => format!(
                "write deflate {path} off={off} clen={compressed_len} dlen={decompressed_len}"
            ),
            DataSource::Zeros { len } => format!("write zeros {path} off={off} len={len}"),
        };
        self.calls.push(line);
        Ok(())
    }

    fn write_empty_block(
        &mut self,
        target: &TargetPath,
        off: u64,
        blocks: u32,
    ) -> Result<(), Error> {
        self.calls.push(format!(
            "empty {} off={off} blocks={blocks}",
            target.as_path().display()
        ));
        Ok(())
    }

    fn truncate(&mut self, target: &TargetPath, len: u64) -> Result<(), Error> {
        self.calls
            .push(format!("truncate {} len={len}", target.as_path().display()));
        Ok(())
    }

    fn remove_file(&mut self, target: &TargetPath) -> Result<(), Error> {
        self.calls
            .push(format!("remove {}", target.as_path().display()));
        Ok(())
    }

    fn remove_expansion(&mut self, exp: u16, _keep: &KeepFilter) -> Result<(), Error> {
        self.calls.push(format!("remove_expansion {exp}"));
        Ok(())
    }

    fn make_dir_tree(&mut self, rel: &SafePath) -> Result<(), Error> {
        self.calls
            .push(format!("mkdir {}", rel.as_path().display()));
        Ok(())
    }

    fn remove_dir(&mut self, rel: &SafePath) -> Result<(), Error> {
        self.calls
            .push(format!("rmdir {}", rel.as_path().display()));
        Ok(())
    }
}
