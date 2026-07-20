//! The FFXIV patchlist block-hash scheme: one SHA1 over each fixed-size block of a file.
//!
//! A file verified this way carries a SHA1 per block; a block that fails is re-fetched on its own,
//! never the whole file. This module owns the layout math ([`BlockPlan`]) and the hashing of one block
//! from disk ([`hash_block`]); the concurrent verification and re-fetch live with the transfer engine.

use std::io::{Read, Seek, SeekFrom};
use std::ops::Range;
use std::path::Path;

use sha1::{Digest, Sha1};

/// The buffer size for reading a block back off disk to hash it.
const READ_CHUNK: usize = 64 * 1024;

/// The block layout of a file: a SHA1 per fixed-size block over `[0, len)`. The last block is short
/// when `len` is not a multiple of the block size.
#[allow(dead_code)] // consumed by the segmented engine's block verifier
pub(crate) struct BlockPlan {
    block_size: u64,
    len: u64,
    hashes: Vec<[u8; 20]>,
}

#[allow(dead_code)] // consumed by the segmented engine's block verifier
impl BlockPlan {
    /// Build a plan from a validator's `block_size`/`hashes` and the file's total length. The spec
    /// builder has already checked `hashes.len() == len.div_ceil(block_size)` and `block_size > 0`.
    pub(crate) fn new(block_size: u32, hashes: Vec<[u8; 20]>, len: u64) -> Self {
        Self {
            block_size: u64::from(block_size),
            len,
            hashes,
        }
    }

    /// The number of blocks.
    pub(crate) fn count(&self) -> u32 {
        self.hashes.len() as u32
    }

    /// The half-open byte range block `i` covers; the last block is short when `len` is not a multiple
    /// of the block size.
    pub(crate) fn block_range(&self, i: u32) -> Range<u64> {
        let start = u64::from(i) * self.block_size;
        let end = (start + self.block_size).min(self.len);
        start..end
    }

    /// The expected SHA1 of block `i`.
    pub(crate) fn expected(&self, i: u32) -> [u8; 20] {
        self.hashes[i as usize]
    }
}

/// SHA1 the byte range `range` of the file at `part`, reading in bounded memory. Meant to run on a
/// blocking worker (`spawn_blocking`): it uses positioned reads on a fresh handle, so it never touches
/// the async transfer path and never contends with a worker writing a different block.
#[allow(dead_code)] // consumed by the segmented engine's block verifier
pub(crate) fn hash_block(part: &Path, range: Range<u64>) -> std::io::Result<[u8; 20]> {
    let mut file = std::fs::File::open(part)?;
    file.seek(SeekFrom::Start(range.start))?;
    let mut remaining = range.end - range.start;
    let mut hasher = Sha1::new();
    let mut buf = vec![0u8; READ_CHUNK];
    while remaining > 0 {
        let want = remaining.min(READ_CHUNK as u64) as usize;
        let read = file.read(&mut buf[..want])?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        hasher.update(&buf[..read]);
        remaining -= read as u64;
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sha1_of(bytes: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(bytes);
        h.finalize().into()
    }

    #[test]
    fn block_ranges_tile_the_file_with_a_short_last_block() {
        let plan = BlockPlan::new(16, vec![[0u8; 20]; 3], 40);
        assert_eq!(plan.count(), 3);
        assert_eq!(plan.block_range(0), 0..16);
        assert_eq!(plan.block_range(1), 16..32);
        assert_eq!(plan.block_range(2), 32..40); // short last block
    }

    #[test]
    fn an_exact_multiple_has_full_final_block() {
        let plan = BlockPlan::new(16, vec![[0u8; 20]; 2], 32);
        assert_eq!(plan.block_range(1), 16..32);
    }

    #[test]
    fn a_file_smaller_than_a_block_is_one_block() {
        let plan = BlockPlan::new(64, vec![[0u8; 20]], 10);
        assert_eq!(plan.count(), 1);
        assert_eq!(plan.block_range(0), 0..10);
    }

    #[test]
    fn hash_block_matches_a_direct_hash_of_the_span() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let body: Vec<u8> = (0..100u32).map(|n| n as u8).collect();
        file.write_all(&body).unwrap();
        file.flush().unwrap();
        // A middle span and the trailing span, each hashed two ways.
        assert_eq!(
            hash_block(file.path(), 16..32).unwrap(),
            sha1_of(&body[16..32])
        );
        assert_eq!(
            hash_block(file.path(), 96..100).unwrap(),
            sha1_of(&body[96..100])
        );
    }

    #[test]
    fn hash_block_past_the_end_is_an_error_not_a_short_hash() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0u8; 10]).unwrap();
        file.flush().unwrap();
        assert!(hash_block(file.path(), 0..20).is_err());
    }
}
