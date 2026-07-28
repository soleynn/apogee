//! The model entry's section table, and the file header an extraction has to put back.
//!
//! A model is stored as eleven sections rather than one stream: a vertex-declaration stack, a
//! runtime block, and a vertex, edge-geometry and index buffer for each of three levels of detail.
//! Each section names its own run of blocks, so the game can pull one level of detail without
//! touching the rest.
//!
//! The 68-byte header a model file opens with is **not** stored: the packer folds its fields into
//! the entry header, so an extraction writes it back from those fields, with the offsets and sizes
//! recomputed from what the blocks actually decode to. The entry header's own size words are those
//! lengths rounded up to 128 bytes (the padding between sections in the packed file, which the
//! archive does not store), so they cannot be copied through: the header this writes is the one that
//! describes the bytes beside it.

use crate::bytes::{self, Cursor};
use crate::error::{Error, Result};

/// How many levels of detail a model entry's tables always describe.
pub const MODEL_LOD_COUNT: usize = 3;

/// The byte length of the header a model file opens with.
pub const MODEL_FILE_HEADER_LEN: usize = 68;

/// Where a model entry's block-size array starts, and so the length of its fixed table.
pub const MODEL_TABLE_OFFSET: usize = 0xD0;

/// One section's run of blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockRun {
    /// The section's first block, indexing [`ModelTable::block_sizes`].
    pub first: u16,
    /// How many blocks the section spans.
    pub count: u16,
}

impl BlockRun {
    /// The block indexes this run covers, or `None` if it runs past `total`.
    fn range(&self, total: usize) -> Option<std::ops::Range<usize>> {
        let start = usize::from(self.first);
        let end = start.checked_add(usize::from(self.count))?;
        (end <= total).then_some(start..end)
    }
}

/// Which section of a model a run of blocks belongs to, in the order an extraction writes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelSection {
    /// The vertex declarations.
    Stack,
    /// The runtime block: strings, bone tables and the rest the game reads at load.
    Runtime,
    /// One level of detail's vertex buffer.
    Vertex(u8),
    /// One level of detail's edge-geometry vertex buffer. Empty in every model observed.
    EdgeGeometry(u8),
    /// One level of detail's index buffer.
    Index(u8),
}

/// A model entry's fixed table: every section's size, offset and run of blocks, then the on-disk
/// size of each block.
///
/// The `*_size` fields are the packed file's section lengths, rounded up to 128 bytes; the
/// `compressed_*` and `*_offset` fields describe the data region as stored. Nothing here is
/// interpreted beyond locating blocks: what a vertex buffer means is the caller's business.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelTable {
    /// The model format's version word, carried into the header an extraction writes.
    pub version: u32,
    /// The stack section's length, rounded up to 128 bytes.
    pub stack_size: u32,
    /// The runtime section's length, rounded up to 128 bytes.
    pub runtime_size: u32,
    /// Each level of detail's vertex-buffer length, rounded up to 128 bytes.
    pub vertex_size: [u32; MODEL_LOD_COUNT],
    /// Each level of detail's edge-geometry length, rounded up to 128 bytes.
    pub edge_size: [u32; MODEL_LOD_COUNT],
    /// Each level of detail's index-buffer length, rounded up to 128 bytes.
    pub index_size: [u32; MODEL_LOD_COUNT],
    /// What the stack section occupies on disk.
    pub compressed_stack_size: u32,
    /// What the runtime section occupies on disk.
    pub compressed_runtime_size: u32,
    /// What each vertex buffer occupies on disk.
    pub compressed_vertex_size: [u32; MODEL_LOD_COUNT],
    /// What each edge-geometry buffer occupies on disk.
    pub compressed_edge_size: [u32; MODEL_LOD_COUNT],
    /// What each index buffer occupies on disk.
    pub compressed_index_size: [u32; MODEL_LOD_COUNT],
    /// The stack section's byte offset within the data region.
    pub stack_offset: u32,
    /// The runtime section's byte offset within the data region.
    pub runtime_offset: u32,
    /// Each vertex buffer's byte offset within the data region.
    pub vertex_offset: [u32; MODEL_LOD_COUNT],
    /// Each edge-geometry buffer's byte offset within the data region.
    pub edge_offset: [u32; MODEL_LOD_COUNT],
    /// Each index buffer's byte offset within the data region.
    pub index_offset: [u32; MODEL_LOD_COUNT],
    /// The stack section's run of blocks.
    pub stack_blocks: BlockRun,
    /// The runtime section's run of blocks.
    pub runtime_blocks: BlockRun,
    /// Each vertex buffer's run of blocks.
    pub vertex_blocks: [BlockRun; MODEL_LOD_COUNT],
    /// Each edge-geometry buffer's run of blocks.
    pub edge_blocks: [BlockRun; MODEL_LOD_COUNT],
    /// Each index buffer's run of blocks.
    pub index_blocks: [BlockRun; MODEL_LOD_COUNT],
    /// How many vertex declarations the stack section holds.
    pub vertex_declaration_count: u16,
    /// How many materials the model references.
    pub material_count: u16,
    /// How many levels of detail the model uses, however many the tables describe.
    pub lod_count: u8,
    /// The format's index-buffer-streaming flag, carried through verbatim.
    pub index_buffer_streaming: u8,
    /// The format's edge-geometry flag, carried through verbatim.
    pub edge_geometry: u8,
    /// The header's trailing pad byte, carried through so the written header matches.
    pub padding: u8,
    /// Every block's on-disk size, in the order the sections index them.
    pub block_sizes: Vec<u16>,
}

impl ModelTable {
    /// Parse a model entry's table from the entry's header region.
    ///
    /// # Errors
    /// [`Error::EntryCorrupt`] if the fixed table or the block-size array does not fit inside the
    /// declared header, or if a section's run of blocks names one the array does not hold.
    pub fn parse(head: &[u8], offset: u64) -> Result<Self> {
        let fixed = head.get(..MODEL_TABLE_OFFSET).ok_or(Error::EntryCorrupt {
            offset,
            detail: "entry table does not fit inside the declared header",
        })?;
        let mut c = Cursor::new(fixed, offset);
        c.skip(0x14)?; // the five words every entry header shares
        let version = c.u32_le()?;
        let stack_size = c.u32_le()?;
        let runtime_size = c.u32_le()?;
        let vertex_size = lods_u32(&mut c)?;
        let edge_size = lods_u32(&mut c)?;
        let index_size = lods_u32(&mut c)?;
        let compressed_stack_size = c.u32_le()?;
        let compressed_runtime_size = c.u32_le()?;
        let compressed_vertex_size = lods_u32(&mut c)?;
        let compressed_edge_size = lods_u32(&mut c)?;
        let compressed_index_size = lods_u32(&mut c)?;
        let stack_offset = c.u32_le()?;
        let runtime_offset = c.u32_le()?;
        let vertex_offset = lods_u32(&mut c)?;
        let edge_offset = lods_u32(&mut c)?;
        let index_offset = lods_u32(&mut c)?;
        let stack_blocks = BlockRun {
            first: c.u16_le()?,
            ..BlockRun::default()
        };
        let runtime_first = c.u16_le()?;
        let vertex_first = lods_u16(&mut c)?;
        let edge_first = lods_u16(&mut c)?;
        let index_first = lods_u16(&mut c)?;
        let stack_count = c.u16_le()?;
        let runtime_count = c.u16_le()?;
        let vertex_count = lods_u16(&mut c)?;
        let edge_count = lods_u16(&mut c)?;
        let index_count = lods_u16(&mut c)?;
        let vertex_declaration_count = c.u16_le()?;
        let material_count = c.u16_le()?;
        let lod_count = c.u8()?;
        let index_buffer_streaming = c.u8()?;
        let edge_geometry = c.u8()?;
        let padding = c.u8()?;

        let runs = |first: [u16; MODEL_LOD_COUNT], count: [u16; MODEL_LOD_COUNT]| {
            std::array::from_fn(|i| BlockRun {
                first: first[i],
                count: count[i],
            })
        };
        let table = Self {
            version,
            stack_size,
            runtime_size,
            vertex_size,
            edge_size,
            index_size,
            compressed_stack_size,
            compressed_runtime_size,
            compressed_vertex_size,
            compressed_edge_size,
            compressed_index_size,
            stack_offset,
            runtime_offset,
            vertex_offset,
            edge_offset,
            index_offset,
            stack_blocks: BlockRun {
                first: stack_blocks.first,
                count: stack_count,
            },
            runtime_blocks: BlockRun {
                first: runtime_first,
                count: runtime_count,
            },
            vertex_blocks: runs(vertex_first, vertex_count),
            edge_blocks: runs(edge_first, edge_count),
            index_blocks: runs(index_first, index_count),
            vertex_declaration_count,
            material_count,
            lod_count,
            index_buffer_streaming,
            edge_geometry,
            padding,
            block_sizes: Vec::new(),
        };

        let total = table.declared_block_count();
        let len = usize::try_from(total)
            .ok()
            .and_then(|n| n.checked_mul(2))
            .ok_or(Error::EntryCorrupt {
                offset,
                detail: "entry table extent overflows",
            })?;
        let raw = head
            .get(MODEL_TABLE_OFFSET..MODEL_TABLE_OFFSET + len)
            .ok_or(Error::EntryCorrupt {
                offset,
                detail: "entry table does not fit inside the declared header",
            })?;
        let mut c = Cursor::new(raw, offset.saturating_add(MODEL_TABLE_OFFSET as u64));
        let mut block_sizes = Vec::with_capacity(raw.len() / 2);
        while c.remaining() >= 2 {
            block_sizes.push(c.u16_le()?);
        }

        let mut table = Self {
            block_sizes,
            ..table
        };
        // Every section has to name blocks the array actually holds, or the extraction below would
        // be reading somebody else's bytes.
        for (_, run) in table.sections() {
            if run.range(table.block_sizes.len()).is_none() {
                return Err(Error::EntryCorrupt {
                    offset,
                    detail: "a model section names blocks the entry does not hold",
                });
            }
        }
        table.block_sizes.shrink_to_fit();
        Ok(table)
    }

    /// How many blocks the section runs add up to.
    fn declared_block_count(&self) -> u64 {
        self.sections()
            .into_iter()
            .map(|(_, run)| u64::from(run.count))
            .sum()
    }

    /// The sections in the order an extraction writes them: the stack, the runtime block, then each
    /// level of detail's vertex, edge-geometry and index buffers.
    #[must_use]
    pub fn sections(&self) -> [(ModelSection, BlockRun); 2 + 3 * MODEL_LOD_COUNT] {
        let mut out = [(ModelSection::Stack, BlockRun::default()); 2 + 3 * MODEL_LOD_COUNT];
        out[0] = (ModelSection::Stack, self.stack_blocks);
        out[1] = (ModelSection::Runtime, self.runtime_blocks);
        for lod in 0..MODEL_LOD_COUNT {
            // The narrowing is over a fixed three-element loop.
            let n = lod as u8;
            out[2 + lod * 3] = (ModelSection::Vertex(n), self.vertex_blocks[lod]);
            out[3 + lod * 3] = (ModelSection::EdgeGeometry(n), self.edge_blocks[lod]);
            out[4 + lod * 3] = (ModelSection::Index(n), self.index_blocks[lod]);
        }
        out
    }

    /// Where a run of blocks starts in the data region, with the blocks it covers. The blocks tile
    /// the region in index order, so a run starts at the sum of every size before it.
    pub(crate) fn run_extent(&self, run: BlockRun) -> Option<(u64, &[u16])> {
        let range = run.range(self.block_sizes.len())?;
        let start: u64 = self.block_sizes[..range.start]
            .iter()
            .map(|s| u64::from(*s))
            .sum();
        Some((start, &self.block_sizes[range]))
    }

    /// The 68-byte header a model file opens with, describing sections of the given lengths laid out
    /// back to back after it. An empty section is given a zero offset rather than a position, which
    /// is how the format spells "this level of detail has none".
    pub(crate) fn file_header(
        &self,
        lengths: &[u64; 2 + 3 * MODEL_LOD_COUNT],
    ) -> [u8; MODEL_FILE_HEADER_LEN] {
        let mut at = MODEL_FILE_HEADER_LEN as u64;
        let mut offsets = [0u32; 2 + 3 * MODEL_LOD_COUNT];
        for (i, len) in lengths.iter().enumerate() {
            offsets[i] = if *len == 0 {
                0
            } else {
                u32::try_from(at).unwrap_or(u32::MAX)
            };
            at += len;
        }
        let size = |i: usize| u32::try_from(lengths[i]).unwrap_or(u32::MAX);

        let mut out = [0u8; MODEL_FILE_HEADER_LEN];
        let mut put32 =
            |at: usize, v: u32| out[at..at + 4].copy_from_slice(&bytes::write_u32_le(v));
        put32(0x00, self.version);
        put32(0x04, size(0));
        put32(0x08, size(1));
        out[0x0C..0x0E].copy_from_slice(&bytes::write_u16_le(self.vertex_declaration_count));
        out[0x0E..0x10].copy_from_slice(&bytes::write_u16_le(self.material_count));
        for lod in 0..MODEL_LOD_COUNT {
            let vertex = 2 + lod * 3;
            let index = 4 + lod * 3;
            out[0x10 + lod * 4..0x14 + lod * 4]
                .copy_from_slice(&bytes::write_u32_le(offsets[vertex]));
            out[0x1C + lod * 4..0x20 + lod * 4]
                .copy_from_slice(&bytes::write_u32_le(offsets[index]));
            out[0x28 + lod * 4..0x2C + lod * 4].copy_from_slice(&bytes::write_u32_le(size(vertex)));
            out[0x34 + lod * 4..0x38 + lod * 4].copy_from_slice(&bytes::write_u32_le(size(index)));
        }
        out[0x40] = self.lod_count;
        out[0x41] = self.index_buffer_streaming;
        out[0x42] = self.edge_geometry;
        out[0x43] = self.padding;
        out
    }
}

fn lods_u32(c: &mut Cursor<'_>) -> Result<[u32; MODEL_LOD_COUNT]> {
    Ok([c.u32_le()?, c.u32_le()?, c.u32_le()?])
}

fn lods_u16(c: &mut Cursor<'_>) -> Result<[u16; MODEL_LOD_COUNT]> {
    Ok([c.u16_le()?, c.u16_le()?, c.u16_le()?])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_covers_only_blocks_the_entry_holds() {
        let run = BlockRun { first: 2, count: 3 };
        assert_eq!(run.range(5), Some(2..5));
        assert_eq!(run.range(4), None);
        assert_eq!(BlockRun { first: 0, count: 0 }.range(0), Some(0..0));
        assert_eq!(
            BlockRun {
                first: u16::MAX,
                count: u16::MAX
            }
            .range(4),
            None
        );
    }

    #[test]
    fn the_written_header_places_each_section_after_the_one_before_it() {
        let table = ModelTable {
            version: 0x0100_0006,
            vertex_declaration_count: 6,
            material_count: 2,
            lod_count: 3,
            ..blank()
        };
        // Stack 816, runtime 9584, then one level of detail with a vertex and an index buffer.
        let lengths = [816, 9584, 4000, 0, 500, 0, 0, 0, 0, 0, 0];
        let head = table.file_header(&lengths);
        assert_eq!(
            u32::from_le_bytes([head[0], head[1], head[2], head[3]]),
            0x0100_0006
        );
        let word =
            |at: usize| u32::from_le_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]);
        assert_eq!(word(0x04), 816);
        assert_eq!(word(0x08), 9584);
        assert_eq!(word(0x10), 68 + 816 + 9584); // first vertex buffer
        assert_eq!(word(0x1C), 68 + 816 + 9584 + 4000); // first index buffer
        assert_eq!(word(0x28), 4000);
        assert_eq!(word(0x34), 500);
        // A level of detail with nothing in it is spelled with a zero offset, not a position.
        assert_eq!(word(0x14), 0);
        assert_eq!(word(0x20), 0);
        assert_eq!(head[0x40], 3);
    }

    fn blank() -> ModelTable {
        ModelTable {
            version: 0,
            stack_size: 0,
            runtime_size: 0,
            vertex_size: [0; 3],
            edge_size: [0; 3],
            index_size: [0; 3],
            compressed_stack_size: 0,
            compressed_runtime_size: 0,
            compressed_vertex_size: [0; 3],
            compressed_edge_size: [0; 3],
            compressed_index_size: [0; 3],
            stack_offset: 0,
            runtime_offset: 0,
            vertex_offset: [0; 3],
            edge_offset: [0; 3],
            index_offset: [0; 3],
            stack_blocks: BlockRun::default(),
            runtime_blocks: BlockRun::default(),
            vertex_blocks: [BlockRun::default(); 3],
            edge_blocks: [BlockRun::default(); 3],
            index_blocks: [BlockRun::default(); 3],
            vertex_declaration_count: 0,
            material_count: 0,
            lod_count: 0,
            index_buffer_streaming: 0,
            edge_geometry: 0,
            padding: 0,
            block_sizes: Vec::new(),
        }
    }
}
