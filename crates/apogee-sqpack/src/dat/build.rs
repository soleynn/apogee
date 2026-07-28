//! A synthetic dat writer for tests. Deliberately not a public API: this crate reads archives and
//! never writes them, and the only reason to lay these bytes out is to prove the reader reads them.
//!
//! Knowing the format well enough to write it is what makes the reader's tests worth anything: the
//! builder places entries at real slot boundaries, pads blocks the way the format does, and can be
//! told to write a deliberately wrong table.

use std::io::Write as _;

use crate::bytes;
use crate::codec::{BLOCK_HEADER_LEN, STORED_SENTINEL, padded_block_len};
use crate::container::{COMMON_HEADER_LEN, SQPACK_MAGIC};

use super::model::{MODEL_LOD_COUNT, MODEL_TABLE_OFFSET};
use super::{DATA_HEADER_LEN, DATA_HEADER_OFFSET, DATA_UNIT, ENTRY_HEADER_LEN};

/// How a block's payload is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Packing {
    /// Raw DEFLATE, the way a real archive stores anything that compresses.
    Deflate,
    /// The stored sentinel, for content DEFLATE would not shrink.
    Stored,
}

/// One entry to lay down.
#[derive(Debug, Clone)]
pub(crate) enum EntrySpec {
    /// A placeholder whose leftover words describe a slot that is no longer there.
    Empty { raw_size: u32, allocated_units: u32 },
    /// A standard file, one block per chunk given.
    Standard {
        chunks: Vec<Vec<u8>>,
        packing: Packing,
    },
    /// A texture: the uncompressed format header, then one chunk per mip level.
    Texture { header: Vec<u8>, mips: Vec<Vec<u8>> },
    /// A model: the eleven sections in the order an extraction writes them, and the fields the
    /// written file header carries. Boxed so one arm does not set the size of every spec.
    Model(Box<ModelSpec>),
    /// A content type this crate does not read.
    Unknown { word: u32 },
}

/// A model entry's sections and the fields its written file header carries.
#[derive(Debug, Clone)]
pub(crate) struct ModelSpec {
    pub(crate) sections: [Vec<u8>; 2 + 3 * MODEL_LOD_COUNT],
    pub(crate) version: u32,
    pub(crate) vertex_declaration_count: u16,
    pub(crate) material_count: u16,
    pub(crate) lod_count: u8,
}

impl EntrySpec {
    /// A standard entry over the given chunks, one block each, DEFLATE-packed.
    pub(crate) fn standard(chunks: Vec<Vec<u8>>) -> Self {
        EntrySpec::Standard {
            chunks,
            packing: Packing::Deflate,
        }
    }

    /// A standard entry whose blocks are stored rather than compressed.
    pub(crate) fn standard_stored(chunks: Vec<Vec<u8>>) -> Self {
        EntrySpec::Standard {
            chunks,
            packing: Packing::Stored,
        }
    }

    /// An empty entry whose remaining words still describe its slot's previous occupant.
    pub(crate) fn empty_with_leftovers(raw_size: u32, allocated_units: u32) -> Self {
        EntrySpec::Empty {
            raw_size,
            allocated_units,
        }
    }

    /// A texture entry: an uncompressed format header and one block per mip level.
    pub(crate) fn texture(header: Vec<u8>, mips: Vec<Vec<u8>>) -> Self {
        EntrySpec::Texture { header, mips }
    }

    /// A model entry whose sections are given in the order an extraction writes them: the stack, the
    /// runtime block, then each level of detail's vertex, edge-geometry and index buffers.
    pub(crate) fn model(sections: [Vec<u8>; 2 + 3 * MODEL_LOD_COUNT]) -> Self {
        EntrySpec::Model(Box::new(ModelSpec {
            sections,
            version: 0x0100_0006,
            vertex_declaration_count: 6,
            material_count: 2,
            lod_count: 3,
        }))
    }

    /// An entry declaring a content type outside the known set.
    pub(crate) fn unknown_type(word: u32) -> Self {
        EntrySpec::Unknown { word }
    }
}

/// One block's bytes: header, payload, and the padding up to the 128-byte boundary.
pub(crate) fn block_bytes(plain: &[u8], packing: Packing) -> Vec<u8> {
    let (payload, declared) = match packing {
        Packing::Stored => (plain.to_vec(), STORED_SENTINEL),
        Packing::Deflate => {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(plain).unwrap();
            let deflated = encoder.finish().unwrap();
            let len = deflated.len() as u32;
            (deflated, len)
        }
    };
    let mut out = Vec::new();
    out.extend_from_slice(&bytes::write_u32_le(BLOCK_HEADER_LEN));
    out.extend_from_slice(&bytes::write_u32_le(0));
    out.extend_from_slice(&bytes::write_u32_le(declared));
    out.extend_from_slice(&bytes::write_u32_le(plain.len() as u32));
    out.extend_from_slice(&payload);
    let total = padded_block_len(payload.len() as u32).unwrap() as usize;
    out.resize(total, 0);
    out
}

/// Which slot of the model header's run table each section is written into. The table groups its
/// runs by kind (every vertex buffer, then every edge-geometry buffer, then every index buffer)
/// while an extraction walks them level by level, so the two orders are not the same one.
const RUN_SLOT: [usize; 2 + 3 * MODEL_LOD_COUNT] = [0, 1, 2, 5, 8, 3, 6, 9, 4, 7, 10];

/// Round a data-region length up to the unit the entry header counts in.
fn units(len: usize) -> u32 {
    len.div_ceil(DATA_UNIT as usize) as u32
}

/// Pad a header out to the 128-byte multiple that holds it, the way a real entry is laid out.
fn pad_header(mut head: Vec<u8>) -> Vec<u8> {
    let padded = head.len().div_ceil(DATA_UNIT as usize) * DATA_UNIT as usize;
    head.resize(padded, 0);
    head
}

/// Builds a byte-faithful dat container: the common header, the data header, then entries laid out
/// back to back from `0x800`.
#[derive(Debug, Clone, Default)]
pub(crate) struct DatBuilder {
    entries: Vec<EntrySpec>,
    /// Extra slack to leave after each entry's data, in 128-byte units.
    slack_units: u32,
    container_kind: Option<u32>,
    /// Write the first twenty-four bytes the way the spanned dat files with no magic carry them.
    no_magic: bool,
    max_file_size: u32,
    span_index: u32,
}

/// Where an entry was written, and what it should extract to.
#[derive(Debug, Clone)]
pub(crate) struct Placed {
    pub(crate) offset: u64,
    pub(crate) content: Vec<u8>,
}

impl DatBuilder {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
            slack_units: 0,
            container_kind: None,
            no_magic: false,
            max_file_size: 2_000_000_000,
            span_index: 1,
        }
    }

    pub(crate) fn entry(&mut self, spec: EntrySpec) -> &mut Self {
        self.entries.push(spec);
        self
    }

    /// Leave `units` of unused space after every entry's data, the way an archive that shrank a file
    /// in place leaves the rest of its slot reserved.
    pub(crate) fn slack(&mut self, units: u32) -> &mut Self {
        self.slack_units = units;
        self
    }

    /// Declare a container type other than "data" in the common header.
    pub(crate) fn container_kind(&mut self, kind: u32) -> &mut Self {
        self.container_kind = Some(kind);
        self
    }

    /// Write the twenty-four-byte blob the spanned dat files with no `SqPack` magic carry in place
    /// of a common header, which is what nineteen of a full install's eighty-six dat files hold.
    pub(crate) fn no_magic(&mut self) -> &mut Self {
        self.no_magic = true;
        self
    }

    /// The container's bytes, and where each entry landed with the content it holds.
    pub(crate) fn build(&self) -> (Vec<u8>, Vec<Placed>) {
        let mut out = vec![0u8; COMMON_HEADER_LEN];
        if self.no_magic {
            for (at, word) in [(0x00, 128u32), (0x0C, 15), (0x14, 2)] {
                out[at..at + 4].copy_from_slice(&bytes::write_u32_le(word));
            }
        } else {
            out[0..8].copy_from_slice(&SQPACK_MAGIC);
            out[0x0C..0x10].copy_from_slice(&bytes::write_u32_le(COMMON_HEADER_LEN as u32));
            out[0x10..0x14].copy_from_slice(&bytes::write_u32_le(1));
            out[0x14..0x18].copy_from_slice(&bytes::write_u32_le(self.container_kind.unwrap_or(1)));
        }

        let mut data = vec![0u8; DATA_HEADER_LEN as usize];
        data[0x00..0x04].copy_from_slice(&bytes::write_u32_le(DATA_HEADER_LEN));
        data[0x08..0x0C].copy_from_slice(&bytes::write_u32_le(16));
        data[0x10..0x14].copy_from_slice(&bytes::write_u32_le(self.span_index));
        data[0x18..0x1C].copy_from_slice(&bytes::write_u32_le(self.max_file_size));

        let mut region = Vec::new();
        let mut placed = Vec::new();
        for spec in &self.entries {
            let offset = DATA_HEADER_OFFSET + u64::from(DATA_HEADER_LEN) + region.len() as u64;
            let (bytes_out, content) = self.entry_bytes(spec);
            region.extend_from_slice(&bytes_out);
            placed.push(Placed { offset, content });
        }

        data[0x0C..0x10].copy_from_slice(&bytes::write_u32_le(units(region.len())));
        out.extend_from_slice(&data);
        out.extend_from_slice(&region);
        (out, placed)
    }

    /// The container's bytes alone.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.build().0
    }

    /// One entry: its header, its data region, and the content it extracts to.
    fn entry_bytes(&self, spec: &EntrySpec) -> (Vec<u8>, Vec<u8>) {
        let (mut head, data, content) = match spec {
            EntrySpec::Empty {
                raw_size,
                allocated_units,
            } => {
                let mut head = entry_head(1, *raw_size, *allocated_units, 0);
                head.extend_from_slice(&bytes::write_u32_le(0));
                (head, Vec::new(), Vec::new())
            }
            EntrySpec::Unknown { word } => {
                let head = entry_head(*word, 0, 0, 0);
                (head, Vec::new(), Vec::new())
            }
            EntrySpec::Standard { chunks, packing } => {
                let mut table = Vec::new();
                let mut data = Vec::new();
                let mut content = Vec::new();
                for chunk in chunks {
                    let block = block_bytes(chunk, *packing);
                    table.extend_from_slice(&bytes::write_u32_le(data.len() as u32));
                    table.extend_from_slice(&bytes::write_u16_le(block.len() as u16));
                    table.extend_from_slice(&bytes::write_u16_le(chunk.len() as u16));
                    data.extend_from_slice(&block);
                    content.extend_from_slice(chunk);
                }
                let mut head = entry_head(
                    2,
                    content.len() as u32,
                    units(data.len()) + self.slack_units,
                    units(data.len()),
                );
                head.extend_from_slice(&bytes::write_u32_le(chunks.len() as u32));
                head.extend_from_slice(&table);
                (head, data, content)
            }
            EntrySpec::Texture { header, mips } => {
                let mut table = Vec::new();
                let mut sizes = Vec::new();
                let mut data = header.clone();
                let mut content = header.clone();
                for (n, mip) in mips.iter().enumerate() {
                    let block = block_bytes(mip, Packing::Deflate);
                    table.extend_from_slice(&bytes::write_u32_le(data.len() as u32));
                    table.extend_from_slice(&bytes::write_u32_le(block.len() as u32));
                    table.extend_from_slice(&bytes::write_u32_le(mip.len() as u32));
                    table.extend_from_slice(&bytes::write_u32_le(n as u32));
                    table.extend_from_slice(&bytes::write_u32_le(1));
                    sizes.extend_from_slice(&bytes::write_u16_le(block.len() as u16));
                    data.extend_from_slice(&block);
                    content.extend_from_slice(mip);
                }
                let mut head = entry_head(
                    4,
                    content.len() as u32,
                    units(data.len()) + self.slack_units,
                    units(data.len()),
                );
                head.extend_from_slice(&bytes::write_u32_le(mips.len() as u32));
                head.extend_from_slice(&table);
                head.extend_from_slice(&sizes);
                (head, data, content)
            }
            EntrySpec::Model(model) => {
                let ModelSpec {
                    sections,
                    version,
                    vertex_declaration_count,
                    material_count,
                    lod_count,
                } = model.as_ref();
                let mut data = Vec::new();
                let mut sizes = Vec::new();
                let mut runs = Vec::new();
                let mut body = Vec::new();
                for section in sections {
                    let first = sizes.len() as u16;
                    if section.is_empty() {
                        runs.push((first, 0u16));
                        continue;
                    }
                    let block = block_bytes(section, Packing::Deflate);
                    sizes.push(block.len() as u16);
                    data.extend_from_slice(&block);
                    body.extend_from_slice(section);
                    runs.push((first, 1));
                }
                let mut content = model_file_header(
                    *version,
                    *vertex_declaration_count,
                    *material_count,
                    *lod_count,
                    sections,
                );
                content.extend_from_slice(&body);

                let mut head = entry_head(
                    3,
                    content.len() as u32,
                    units(data.len()) + self.slack_units,
                    units(data.len()),
                );
                head.extend_from_slice(&bytes::write_u32_le(*version));
                head.resize(MODEL_TABLE_OFFSET, 0);
                // Only the fields an extraction reads are filled in: the run table, the counts and
                // the flags. The size and offset words a real container also carries are padding
                // the reader is required not to depend on.
                for (i, (first, count)) in runs.iter().enumerate() {
                    let slot = RUN_SLOT[i];
                    let at = 0x9C + slot * 2;
                    head[at..at + 2].copy_from_slice(&bytes::write_u16_le(*first));
                    let at = 0xB2 + slot * 2;
                    head[at..at + 2].copy_from_slice(&bytes::write_u16_le(*count));
                }
                head[0xC8..0xCA].copy_from_slice(&bytes::write_u16_le(*vertex_declaration_count));
                head[0xCA..0xCC].copy_from_slice(&bytes::write_u16_le(*material_count));
                head[0xCC] = *lod_count;
                for size in &sizes {
                    head.extend_from_slice(&bytes::write_u16_le(*size));
                }
                (head, data, content)
            }
        };

        head = pad_header(head);
        let header_size = head.len() as u32;
        head[0x00..0x04].copy_from_slice(&bytes::write_u32_le(header_size));
        let mut out = head;
        let slot = data.len() + (self.slack_units as usize * DATA_UNIT as usize);
        out.extend_from_slice(&data);
        out.resize(
            header_size as usize + slot.div_ceil(DATA_UNIT as usize) * DATA_UNIT as usize,
            0,
        );
        (out, content)
    }
}

/// The five words every entry header opens with, with the header length left to be filled in once
/// the table is laid out.
fn entry_head(kind: u32, raw_size: u32, allocated: u32, occupied: u32) -> Vec<u8> {
    let mut head = Vec::new();
    head.extend_from_slice(&bytes::write_u32_le(0)); // header length, patched once padded
    head.extend_from_slice(&bytes::write_u32_le(kind));
    head.extend_from_slice(&bytes::write_u32_le(raw_size));
    head.extend_from_slice(&bytes::write_u32_le(allocated));
    head.extend_from_slice(&bytes::write_u32_le(occupied));
    debug_assert_eq!(head.len(), ENTRY_HEADER_LEN);
    head
}

/// The 68-byte header a model file opens with, for the content a built model entry extracts to.
fn model_file_header(
    version: u32,
    vertex_declaration_count: u16,
    material_count: u16,
    lod_count: u8,
    sections: &[Vec<u8>; 2 + 3 * MODEL_LOD_COUNT],
) -> Vec<u8> {
    let mut at = 68u32;
    let mut offsets = [0u32; 2 + 3 * MODEL_LOD_COUNT];
    for (i, section) in sections.iter().enumerate() {
        offsets[i] = if section.is_empty() { 0 } else { at };
        at += section.len() as u32;
    }
    let mut out = vec![0u8; 68];
    out[0x00..0x04].copy_from_slice(&bytes::write_u32_le(version));
    out[0x04..0x08].copy_from_slice(&bytes::write_u32_le(sections[0].len() as u32));
    out[0x08..0x0C].copy_from_slice(&bytes::write_u32_le(sections[1].len() as u32));
    out[0x0C..0x0E].copy_from_slice(&bytes::write_u16_le(vertex_declaration_count));
    out[0x0E..0x10].copy_from_slice(&bytes::write_u16_le(material_count));
    for lod in 0..MODEL_LOD_COUNT {
        let vertex = 2 + lod * 3;
        let index = 4 + lod * 3;
        out[0x10 + lod * 4..0x14 + lod * 4].copy_from_slice(&bytes::write_u32_le(offsets[vertex]));
        out[0x1C + lod * 4..0x20 + lod * 4].copy_from_slice(&bytes::write_u32_le(offsets[index]));
        out[0x28 + lod * 4..0x2C + lod * 4]
            .copy_from_slice(&bytes::write_u32_le(sections[vertex].len() as u32));
        out[0x34 + lod * 4..0x38 + lod * 4]
            .copy_from_slice(&bytes::write_u32_le(sections[index].len() as u32));
    }
    out[0x40] = lod_count;
    out
}
