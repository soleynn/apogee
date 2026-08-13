//! A synthetic dat writer for tests, reachable outside the crate only through the `test-fixtures`
//! feature. This crate reads archives and never writes them, so this is not a write API: the only
//! reason to lay these bytes out is to prove the reader reads them.
//!
//! Knowing the format well enough to write it is what makes the reader's tests worth anything: the
//! builder places entries at real slot boundaries, pads blocks the way the format does, and can be
//! told to write a deliberately wrong table.
//!
//! The builder writes into in-memory buffers that cannot fail, so it asserts its own invariants
//! rather than threading a `Result` through every chained call.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;

use crate::bytes;
use crate::codec::{BLOCK_HEADER_LEN, STORED_SENTINEL, padded_block_len};
use crate::container::{COMMON_HEADER_LEN, SQPACK_MAGIC};
use crate::integrity::{
    HeaderId, SELF_HASH_AT, SELF_HASH_LEN, UNCLAIMED_DIGEST, self_hash_slot, sha1,
};

use super::model::{MODEL_LOD_COUNT, MODEL_TABLE_OFFSET};
use super::{
    DATA_HEADER_LEN, DATA_REGION_OFFSET, DATA_UNIT, EMPTY_BLOCK_HEADER_LEN, ENTRY_HEADER_LEN,
    empty_block_header,
};

/// How a block's payload is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packing {
    /// Raw DEFLATE, the way a real archive stores anything that compresses.
    Deflate,
    /// The stored sentinel, for content DEFLATE would not shrink.
    Stored,
}

/// One entry to lay down.
#[derive(Debug, Clone)]
pub enum EntrySpec {
    /// A placeholder whose leftover words describe a slot that is no longer there.
    Empty {
        raw_size: u32,
        allocated_units: u32,
        /// The word a standard entry spends on its block count. A real empty entry carries whatever
        /// its previous occupant left there, which is what a reader must not frame a table from.
        leftover_word: u32,
    },
    /// A standard file, one block per chunk given.
    Standard {
        chunks: Vec<Vec<u8>>,
        packing: Packing,
    },
    /// A texture: the uncompressed format header, then one mip level per group of chunks (a mip
    /// spans as many blocks as the packer needed, so a group of more than one is the ordinary case).
    Texture {
        header: Vec<u8>,
        mips: Vec<Vec<Vec<u8>>>,
        /// A file length to declare instead of the bytes laid down, which is how a volume texture
        /// declares padding between mip surfaces that the archive does not store.
        declares: Option<u32>,
    },
    /// A model: the eleven sections in the order an extraction writes them, and the fields the
    /// written file header carries. Boxed so one arm does not set the size of every spec.
    Model(Box<ModelSpec>),
    /// A content type this crate does not read.
    Unknown { word: u32 },
}

/// A model entry's sections and the fields its written file header carries.
#[derive(Debug, Clone)]
pub struct ModelSpec {
    /// Each section as the blocks it is stored in, in the order an extraction writes them.
    pub sections: [Vec<Vec<u8>>; 2 + 3 * MODEL_LOD_COUNT],
    pub version: u32,
    pub vertex_declaration_count: u16,
    pub material_count: u16,
    pub lod_count: u8,
}

impl EntrySpec {
    /// A standard entry over the given chunks, one block each, DEFLATE-packed.
    pub fn standard(chunks: Vec<Vec<u8>>) -> Self {
        EntrySpec::Standard {
            chunks,
            packing: Packing::Deflate,
        }
    }

    /// A standard entry whose blocks are stored rather than compressed.
    pub fn standard_stored(chunks: Vec<Vec<u8>>) -> Self {
        EntrySpec::Standard {
            chunks,
            packing: Packing::Stored,
        }
    }

    /// An empty entry whose remaining words still describe its slot's previous occupant.
    pub fn empty_with_leftovers(raw_size: u32, allocated_units: u32, leftover_word: u32) -> Self {
        EntrySpec::Empty {
            raw_size,
            allocated_units,
            leftover_word,
        }
    }

    /// A texture entry: an uncompressed format header and one block per mip level.
    pub fn texture(header: Vec<u8>, mips: Vec<Vec<u8>>) -> Self {
        EntrySpec::Texture {
            header,
            mips: mips.into_iter().map(|mip| vec![mip]).collect(),
            declares: None,
        }
    }

    /// A texture entry whose mips span several blocks each, the way a real one over 16 KiB does.
    pub fn texture_blocks(header: Vec<u8>, mips: Vec<Vec<Vec<u8>>>) -> Self {
        EntrySpec::Texture {
            header,
            mips,
            declares: None,
        }
    }

    /// A texture entry that declares a longer file than it stores, the way a volume texture whose
    /// mip surfaces are padded in the file does.
    pub fn texture_declaring(header: Vec<u8>, mips: Vec<Vec<u8>>, declares: u32) -> Self {
        EntrySpec::Texture {
            header,
            mips: mips.into_iter().map(|mip| vec![mip]).collect(),
            declares: Some(declares),
        }
    }

    /// A model entry whose sections are given in the order an extraction writes them: the stack, the
    /// runtime block, then each level of detail's vertex, edge-geometry and index buffers.
    pub fn model(sections: [Vec<u8>; 2 + 3 * MODEL_LOD_COUNT]) -> Self {
        Self::model_blocks(sections.map(|section| {
            if section.is_empty() {
                Vec::new()
            } else {
                vec![section]
            }
        }))
    }

    /// A model entry whose sections span several blocks each.
    pub fn model_blocks(sections: [Vec<Vec<u8>>; 2 + 3 * MODEL_LOD_COUNT]) -> Self {
        EntrySpec::Model(Box::new(ModelSpec {
            sections,
            version: 0x0100_0006,
            vertex_declaration_count: 6,
            material_count: 2,
            lod_count: 3,
        }))
    }

    /// An entry declaring a content type outside the known set.
    pub fn unknown_type(word: u32) -> Self {
        EntrySpec::Unknown { word }
    }
}

/// One block's bytes: header, payload, and the padding up to the 128-byte boundary.
pub fn block_bytes(plain: &[u8], packing: Packing) -> Vec<u8> {
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

/// One thing to lay into the data region, in the order it was asked for.
#[derive(Debug, Clone)]
enum Item {
    /// An entry, with the slack its slot reserves past the data it stores, and whether its slot
    /// words are wiped once its data is laid down.
    Entry {
        spec: EntrySpec,
        slack_units: u32,
        empty_slot_words: bool,
    },
    /// Space no entry claims, as a chain of wiped regions of that many units each.
    Gap(Vec<u32>),
    /// Space no entry claims, verbatim, padded out to a whole unit.
    RawGap(Vec<u8>),
}

/// Builds a byte-faithful dat container: the common header, the data header, then entries and the
/// space between them laid out back to back from `0x800`.
///
/// Byte-faithful includes the four digests a real container carries, so what it builds is clean by
/// default and every hash check has to be provoked deliberately. The two self hashes are written last
/// and the data-region digest before them, so a poke inside a hashed run leaves a container whose
/// hashes are still right about its own bytes.
#[derive(Debug, Clone)]
pub struct DatBuilder {
    items: Vec<Item>,
    /// Slack to leave in the slot of every entry pushed from here on, in 128-byte units.
    slack_units: u32,
    /// Wipe the slot words of every entry pushed from here on.
    empty_slot_words: bool,
    container_kind: Option<u32>,
    /// Write the first twenty-four bytes the way the spanned dat files with no magic carry them.
    no_magic: bool,
    max_file_size: u32,
    span_index: u32,
    unclassified: u32,
    reserved: [u32; 3],
    declared_units: Option<u32>,
    data_sha1: Option<[u8; 20]>,
    self_hashes: [Option<[u8; 20]>; 2],
    header_pokes: Vec<(usize, Vec<u8>)>,
}

/// Where an entry was written, and what it should extract to.
#[derive(Debug, Clone)]
pub struct Placed {
    pub offset: u64,
    pub content: Vec<u8>,
}

/// A built container: its bytes, where its entries landed, and the extent of every run of its data
/// region no entry's slot covers.
#[derive(Debug, Clone)]
pub struct Built {
    pub bytes: Vec<u8>,
    pub placed: Vec<Placed>,
    pub gaps: Vec<(u64, u64)>,
}

impl Default for DatBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DatBuilder {
    /// A container holding nothing, with every header word as a real one spells it.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            slack_units: 0,
            empty_slot_words: false,
            container_kind: None,
            no_magic: false,
            max_file_size: 2_000_000_000,
            span_index: 1,
            unclassified: 16,
            reserved: [0; 3],
            declared_units: None,
            data_sha1: None,
            self_hashes: [None; 2],
            header_pokes: Vec::new(),
        }
    }

    pub fn entry(&mut self, spec: EntrySpec) -> &mut Self {
        let slack_units = self.slack_units;
        let empty_slot_words = self.empty_slot_words;
        self.items.push(Item::Entry {
            spec,
            slack_units,
            empty_slot_words,
        });
        self
    }

    /// Leave `units` of unused space inside the slot of every entry pushed after this, the way an
    /// archive that shrank a file in place leaves the rest of its slot reserved. Slack lives *inside*
    /// a slot; the space between slots is [`DatBuilder::gap`].
    pub fn slack(&mut self, units: u32) -> &mut Self {
        self.slack_units = units;
        self
    }

    /// Write both slot words of every entry pushed after this as zero, while still laying its data
    /// down and its table over it, the way a third-party writer that never fills them does. The
    /// entry still occupies the space it stores, so the container around it is laid out as usual.
    pub fn empty_slot_words(&mut self) -> &mut Self {
        self.empty_slot_words = true;
        self
    }

    /// Leave `units` of space no entry claims, stamped with the marker a patcher writes over a region
    /// it wiped.
    pub fn gap(&mut self, units: u32) -> &mut Self {
        self.gap_chain(&[units])
    }

    /// The same, as several wiped regions back to back, which is what adjacent deletions leave.
    pub fn gap_chain(&mut self, units: &[u32]) -> &mut Self {
        self.items.push(Item::Gap(units.to_vec()));
        self
    }

    /// Leave space no entry claims holding `bytes` verbatim, padded out to a whole unit.
    pub fn raw_gap(&mut self, bytes: Vec<u8>) -> &mut Self {
        self.items.push(Item::RawGap(bytes));
        self
    }

    /// Declare a container type other than "data" in the common header.
    pub fn container_kind(&mut self, kind: u32) -> &mut Self {
        self.container_kind = Some(kind);
        self
    }

    /// Write the twenty-four-byte blob the spanned dat files with no `SqPack` magic carry in place
    /// of a common header, which is what nineteen of a full install's eighty-six dat files hold.
    pub fn no_magic(&mut self) -> &mut Self {
        self.no_magic = true;
        self
    }

    /// Declare a data-region length other than what was laid down.
    pub fn declared_units(&mut self, units: u32) -> &mut Self {
        self.declared_units = Some(units);
        self
    }

    /// Declare `sha1` over the data region instead of the digest of its bytes.
    pub fn data_sha1(&mut self, sha1: [u8; 20]) -> &mut Self {
        self.data_sha1 = Some(sha1);
        self
    }

    /// Declare all zeros over the data region, which claims nothing about it. Two dat files of a full
    /// install do this.
    pub fn zero_data_sha1(&mut self) -> &mut Self {
        self.data_sha1(UNCLAIMED_DIGEST)
    }

    /// Declare `sha1` for one header instead of the digest of its own leading bytes.
    pub fn self_hash(&mut self, header: HeaderId, sha1: [u8; 20]) -> &mut Self {
        self.self_hashes[self_hash_slot(header)] = Some(sha1);
        self
    }

    /// Spell the data header's word at `0x08` as something other than the 16 every container spells.
    pub fn unclassified(&mut self, word: u32) -> &mut Self {
        self.unclassified = word;
        self
    }

    /// Spell one of the data header's three reserved words as something other than zero.
    pub fn reserved(&mut self, index: usize, word: u32) -> &mut Self {
        self.reserved[index] = word;
        self
    }

    /// Declare which of the archive's dat files this is. A full install spells `dat0` and `dat1` both
    /// as 1 in places, so nothing may check it.
    pub fn span_index(&mut self, index: u32) -> &mut Self {
        self.span_index = index;
        self
    }

    /// Declare the length at which the archive rolls over to the next dat file. Eighteen `dat0` files
    /// of a full install are longer than their own value, so nothing may check it either.
    pub fn max_file_size(&mut self, len: u32) -> &mut Self {
        self.max_file_size = len;
        self
    }

    /// Write `bytes` verbatim at absolute offset `at`, which must be inside the two headers. Applied
    /// before the headers' own digests are computed, so a poke inside a hashed run leaves the
    /// container's hashes correct and a poke past one does not.
    pub fn header_pad(&mut self, at: usize, bytes: &[u8]) -> &mut Self {
        self.header_pokes.push((at, bytes.to_vec()));
        self
    }

    /// The container's bytes, and where each entry landed with the content it holds.
    pub fn build(&self) -> (Vec<u8>, Vec<Placed>) {
        let built = self.built();
        (built.bytes, built.placed)
    }

    /// The container's bytes alone.
    pub fn bytes(&self) -> Vec<u8> {
        self.built().bytes
    }

    /// The container, its entries and the extent of every run between their slots.
    pub fn built(&self) -> Built {
        let mut region = Vec::new();
        let mut placed = Vec::new();
        let mut gaps = Vec::new();
        for item in &self.items {
            let at = DATA_REGION_OFFSET + region.len() as u64;
            match item {
                Item::Entry {
                    spec,
                    slack_units,
                    empty_slot_words,
                } => {
                    let (mut bytes_out, content) = self.entry_bytes(spec, *slack_units);
                    if *empty_slot_words {
                        bytes_out[12..ENTRY_HEADER_LEN].fill(0);
                    }
                    region.extend_from_slice(&bytes_out);
                    placed.push(Placed {
                        offset: at,
                        content,
                    });
                }
                Item::Gap(regions) => {
                    let start = region.len();
                    for units in regions {
                        region.extend_from_slice(&empty_block_header(*units));
                        region.resize(
                            region.len() + *units as usize * DATA_UNIT as usize
                                - EMPTY_BLOCK_HEADER_LEN,
                            0,
                        );
                    }
                    gaps.push((at, (region.len() - start) as u64));
                }
                Item::RawGap(raw) => {
                    region.extend_from_slice(raw);
                    region.resize(
                        region.len().div_ceil(DATA_UNIT as usize) * DATA_UNIT as usize,
                        0,
                    );
                    gaps.push((at, DATA_REGION_OFFSET + region.len() as u64 - at));
                }
            }
        }

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
        let word = |data: &mut Vec<u8>, at: usize, value: u32| {
            data[at..at + 4].copy_from_slice(&bytes::write_u32_le(value));
        };
        word(&mut data, 0x00, DATA_HEADER_LEN);
        word(&mut data, 0x04, self.reserved[0]);
        word(&mut data, 0x08, self.unclassified);
        word(
            &mut data,
            0x0C,
            self.declared_units.unwrap_or_else(|| units(region.len())),
        );
        word(&mut data, 0x10, self.span_index);
        word(&mut data, 0x14, self.reserved[1]);
        word(&mut data, 0x18, self.max_file_size);
        word(&mut data, 0x1C, self.reserved[2]);
        let digest = self.data_sha1.unwrap_or_else(|| sha1(&region));
        data[0x20..0x20 + SELF_HASH_LEN].copy_from_slice(&digest);

        out.extend_from_slice(&data);
        out.extend_from_slice(&region);
        for (at, poke) in &self.header_pokes {
            out[*at..*at + poke.len()].copy_from_slice(poke);
        }

        // Each header's own digest covers everything before it, including a container with no magic
        // (nineteen of a full install's dat files, whose digest covers the blob written over it).
        for header in [HeaderId::Common, HeaderId::Second] {
            let at = header.starts_at();
            let digest = self.self_hashes[self_hash_slot(header)]
                .unwrap_or_else(|| sha1(&out[at..at + SELF_HASH_AT]));
            let field = at + SELF_HASH_AT;
            out[field..field + SELF_HASH_LEN].copy_from_slice(&digest);
        }
        Built {
            bytes: out,
            placed,
            gaps,
        }
    }

    /// One entry: its header, its data region, and the content it extracts to.
    fn entry_bytes(&self, spec: &EntrySpec, slack_units: u32) -> (Vec<u8>, Vec<u8>) {
        let (mut head, data, content) = match spec {
            EntrySpec::Empty {
                raw_size,
                allocated_units,
                leftover_word,
            } => {
                let mut head = entry_head(1, *raw_size, *allocated_units, 0);
                head.extend_from_slice(&bytes::write_u32_le(*leftover_word));
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
                    units(data.len()) + slack_units,
                    units(data.len()),
                );
                head.extend_from_slice(&bytes::write_u32_le(chunks.len() as u32));
                head.extend_from_slice(&table);
                (head, data, content)
            }
            EntrySpec::Texture {
                header,
                mips,
                declares,
            } => {
                let mut table = Vec::new();
                let mut sizes = Vec::new();
                let mut data = header.clone();
                let mut content = header.clone();
                let mut first_block = 0u32;
                for mip in mips {
                    let start = data.len() as u32;
                    let mut decompressed = 0u32;
                    for chunk in mip {
                        let block = block_bytes(chunk, Packing::Deflate);
                        sizes.extend_from_slice(&bytes::write_u16_le(block.len() as u16));
                        data.extend_from_slice(&block);
                        content.extend_from_slice(chunk);
                        decompressed += chunk.len() as u32;
                    }
                    table.extend_from_slice(&bytes::write_u32_le(start));
                    table.extend_from_slice(&bytes::write_u32_le(data.len() as u32 - start));
                    table.extend_from_slice(&bytes::write_u32_le(decompressed));
                    table.extend_from_slice(&bytes::write_u32_le(first_block));
                    table.extend_from_slice(&bytes::write_u32_le(mip.len() as u32));
                    first_block += mip.len() as u32;
                }
                let mut head = entry_head(
                    4,
                    declares.unwrap_or(content.len() as u32),
                    units(data.len()) + slack_units,
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
                    for chunk in section {
                        let block = block_bytes(chunk, Packing::Deflate);
                        sizes.push(block.len() as u16);
                        data.extend_from_slice(&block);
                        body.extend_from_slice(chunk);
                    }
                    runs.push((first, section.len() as u16));
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
                    units(data.len()) + slack_units,
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
        let slot = data.len() + (slack_units as usize * DATA_UNIT as usize);
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
    sections: &[Vec<Vec<u8>>; 2 + 3 * MODEL_LOD_COUNT],
) -> Vec<u8> {
    let length = |section: &Vec<Vec<u8>>| section.iter().map(Vec::len).sum::<usize>() as u32;
    let mut at = 68u32;
    let mut offsets = [0u32; 2 + 3 * MODEL_LOD_COUNT];
    for (i, section) in sections.iter().enumerate() {
        offsets[i] = if length(section) == 0 { 0 } else { at };
        at += length(section);
    }
    let mut out = vec![0u8; 68];
    out[0x00..0x04].copy_from_slice(&bytes::write_u32_le(version));
    out[0x04..0x08].copy_from_slice(&bytes::write_u32_le(length(&sections[0])));
    out[0x08..0x0C].copy_from_slice(&bytes::write_u32_le(length(&sections[1])));
    out[0x0C..0x0E].copy_from_slice(&bytes::write_u16_le(vertex_declaration_count));
    out[0x0E..0x10].copy_from_slice(&bytes::write_u16_le(material_count));
    for lod in 0..MODEL_LOD_COUNT {
        let vertex = 2 + lod * 3;
        let index = 4 + lod * 3;
        out[0x10 + lod * 4..0x14 + lod * 4].copy_from_slice(&bytes::write_u32_le(offsets[vertex]));
        out[0x1C + lod * 4..0x20 + lod * 4].copy_from_slice(&bytes::write_u32_le(offsets[index]));
        out[0x28 + lod * 4..0x2C + lod * 4]
            .copy_from_slice(&bytes::write_u32_le(length(&sections[vertex])));
        out[0x34 + lod * 4..0x38 + lod * 4]
            .copy_from_slice(&bytes::write_u32_le(length(&sections[index])));
    }
    out[0x40] = lod_count;
    out
}
