//! [`LocalPatchSource`]: the in-crate [`RangeSource`] that reads byte ranges straight from `.patch`
//! files on disk. It backs each [`PatchId`] with a path (position `i` serves `PatchId(i)`), the same
//! chain order the index recorded, so a repair can pull broken ranges from a local patch cache
//! before falling back to the network range source that lives in `apogee-fetch`.
//!
//! [`Index::source_refs`] names the patches in that order.
//!
//! [`Index::source_refs`]: crate::Index::source_refs

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::ops::Range;
use std::path::PathBuf;

use crate::error::{Error, Op, Result};
use crate::seam::{PatchId, RangeSource};

/// Reads patch byte ranges from local files. `files[i]` serves `PatchId(i)`.
pub struct LocalPatchSource {
    files: Vec<PathBuf>,
}

impl LocalPatchSource {
    /// Back each [`PatchId`] with a local patch file, in the index's chain order: `files[i]` serves
    /// `PatchId(i)`.
    #[must_use]
    pub fn new(files: Vec<PathBuf>) -> Self {
        Self { files }
    }
}

impl RangeSource for LocalPatchSource {
    /// Read each range of one patch file and hand the bytes to `out`. Ranges are the planner's
    /// pre-merged, sorted spans; the file is opened once for the whole call.
    ///
    /// # Errors
    /// [`Error::Corrupt`] if `patch` names no configured file, [`Error::Truncated`] if a range runs
    /// past the file end, [`Error::Io`] on an open/seek/read fault.
    fn read_ranges(
        &mut self,
        patch: PatchId,
        ranges: &[Range<u64>],
        out: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let path = self.files.get(patch.0 as usize).ok_or(Error::Corrupt {
            offset: 0,
            detail: "range source patch id out of range",
        })?;
        let mut file = File::open(path).map_err(|e| Error::io(e, Op::Open))?;
        let mut buf = Vec::new();
        for range in ranges {
            let len = range.end.checked_sub(range.start).ok_or(Error::Corrupt {
                offset: range.start,
                detail: "range source range end precedes start",
            })?;
            file.seek(SeekFrom::Start(range.start))
                .map_err(|e| Error::io(e, Op::Read))?;
            // Grow the buffer only as bytes arrive, so an oversized range reads (at most) the real
            // file rather than pre-allocating the claimed span.
            buf.clear();
            (&mut file)
                .take(len)
                .read_to_end(&mut buf)
                .map_err(|e| Error::io(e, Op::Read))?;
            if buf.len() as u64 != len {
                return Err(Error::Truncated {
                    offset: range.start,
                    needed: len - buf.len() as u64,
                });
            }
            out(range.start, &buf)?;
        }
        Ok(())
    }
}
