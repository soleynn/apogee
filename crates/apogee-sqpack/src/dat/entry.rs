//! Dat entries: the header at the offset an index resolves to, and the tables that say where the
//! file's blocks are.
//!
//! Every entry starts with the same five little-endian words, then a table whose shape depends on
//! the content type:
//!
//! | Offset | Field | Notes |
//! |---|---|---|
//! | 0x00 | u32 header length | the data region begins this many bytes after the entry |
//! | 0x04 | u32 content type | 1 empty, 2 standard, 3 model, 4 texture |
//! | 0x08 | u32 decompressed size | the file's length once extracted |
//! | 0x0C | u32 allocated units | the slot reserved for the entry, in 128-byte units |
//! | 0x10 | u32 occupied units | the data actually stored, in 128-byte units, rounded up |
//!
//! The sixth word is type-specific: a block count for a standard entry, a mip count for a texture,
//! and the model format's own version word for a model. The header is padded to a 128-byte multiple
//! long enough to hold the table, so the table's extent is bounded by the header length itself.
//!
//! An **empty** entry (type 1) carries no data at all. Its remaining words are whatever the slot's
//! previous occupant left there: a real install has entries declaring sizes and block counts that
//! describe nothing, so they are carried verbatim and never acted on.

use crate::bytes::Cursor;
use crate::error::{Error, Result};

use super::model::ModelTable;

/// The unit the allocation and occupancy words count in.
pub const DATA_UNIT: u32 = 128;

/// The bytes every entry header shares before its type-specific table.
pub const ENTRY_HEADER_LEN: usize = 0x14;

/// The byte length of one standard-entry block descriptor.
pub const STANDARD_BLOCK_LEN: usize = 8;

/// The byte length of one texture-entry mip descriptor.
pub const MIP_LEVEL_LEN: usize = 20;

/// A cap on the entry header a parse will read. The largest in a full retail install is 45,184
/// bytes (a standard entry with 5,632 blocks), so this leaves headroom while still refusing to
/// reserve megabytes for a fabricated header length.
pub const DEFAULT_MAX_ENTRY_HEADER_BYTES: u32 = 1 << 20;

/// A cap on the file an extraction will produce. The largest in a full retail install is roughly
/// 86 MiB, so this leaves an order of magnitude while still refusing a fabricated multi-gigabyte
/// size.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1 << 30;

/// Allocation bounds enforced while reading an entry (all SqPack input is hostile).
#[derive(Debug, Clone, Copy)]
pub struct DatLimits {
    /// Refuse an entry whose declared header is longer than this.
    pub max_entry_header_bytes: u32,
    /// Refuse an entry whose declared decompressed size is larger than this.
    pub max_file_bytes: u64,
    /// The per-block bounds handed to the codec.
    pub block: crate::codec::Limits,
}

impl Default for DatLimits {
    fn default() -> Self {
        Self {
            max_entry_header_bytes: DEFAULT_MAX_ENTRY_HEADER_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            block: crate::codec::Limits::default(),
        }
    }
}

/// What kind of content an entry holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ContentType {
    /// A placeholder: the slot holds no file. Written where a patch deleted one.
    Empty,
    /// An ordinary file: a block table followed by its blocks.
    Standard,
    /// A model: a fixed multi-part header naming each section's run of blocks.
    Model,
    /// A texture: one descriptor per mip level, then the blocks.
    Texture,
    /// A type outside the known set, carried verbatim for the inspector to judge.
    Unknown(u32),
}

impl ContentType {
    /// The word an entry header spells this type as.
    #[must_use]
    pub fn word(self) -> u32 {
        match self {
            ContentType::Empty => 1,
            ContentType::Standard => 2,
            ContentType::Model => 3,
            ContentType::Texture => 4,
            ContentType::Unknown(other) => other,
        }
    }

    fn from_word(word: u32) -> Self {
        match word {
            1 => ContentType::Empty,
            2 => ContentType::Standard,
            3 => ContentType::Model,
            4 => ContentType::Texture,
            other => ContentType::Unknown(other),
        }
    }
}

/// The five words every entry header starts with.
///
/// `allocated_units` and `occupied_units` count 128-byte units of the data region: the first is the
/// slot the archive reserved (never smaller than the second, and matched by the distance to the next
/// entry in all but a few percent of a real install, where the surplus is free space), the second
/// the bytes actually stored, rounded up. Both are meaningless on an [`ContentType::Empty`] entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryHeader {
    /// The declared header length, and so the offset of the data region from the entry.
    pub header_size: u32,
    /// What kind of content the entry holds.
    pub content_type: ContentType,
    /// The file's length once extracted.
    pub raw_size: u32,
    /// The slot reserved for the entry, in 128-byte units.
    pub allocated_units: u32,
    /// The data stored in that slot, in 128-byte units, rounded up.
    pub occupied_units: u32,
}

impl EntryHeader {
    /// The slot reserved for the entry's data, in bytes.
    #[must_use]
    pub fn allocated_bytes(&self) -> u64 {
        u64::from(self.allocated_units) * u64::from(DATA_UNIT)
    }

    /// The entry's data as stored, in bytes, rounded up to the unit it is counted in.
    #[must_use]
    pub fn occupied_bytes(&self) -> u64 {
        u64::from(self.occupied_units) * u64::from(DATA_UNIT)
    }

    /// What the entry occupies in its dat file: the header plus the slot reserved after it.
    #[must_use]
    pub fn slot_len(&self) -> u64 {
        u64::from(self.header_size) + self.allocated_bytes()
    }
}

/// One block of a standard entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardBlock {
    /// Byte offset of the block within the entry's data region.
    pub offset: u32,
    /// What the block occupies on disk: its header, payload and padding.
    pub on_disk_size: u16,
    /// What the block decodes to.
    pub decompressed_size: u16,
}

/// One mip level of a texture entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MipLevel {
    /// Byte offset of the mip's first block within the entry's data region.
    pub offset: u32,
    /// What the mip's blocks occupy on disk.
    pub on_disk_size: u32,
    /// What the mip decodes to.
    pub decompressed_size: u32,
    /// The mip's first block, indexing [`TextureTable::block_sizes`].
    pub first_block: u32,
    /// How many blocks the mip spans.
    pub block_count: u32,
}

/// A texture entry's table: one descriptor per mip level, then every block's on-disk size.
///
/// The data region opens with the texture format's own header, stored uncompressed: it runs from the
/// start of the region to the first mip's offset, and an extraction copies it through untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextureTable {
    /// The mip levels, coarsest first as the container writes them.
    pub mips: Vec<MipLevel>,
    /// Every block's on-disk size, in the order the mips index them.
    pub block_sizes: Vec<u16>,
}

impl TextureTable {
    /// The uncompressed header the data region opens with, in bytes.
    #[must_use]
    pub fn raw_header_len(&self) -> u32 {
        self.mips.first().map_or(0, |mip| mip.offset)
    }

    /// What an extraction produces: the uncompressed header plus every mip.
    #[must_use]
    pub fn stored_len(&self) -> u64 {
        self.mips
            .iter()
            .fold(u64::from(self.raw_header_len()), |sum, mip| {
                sum + u64::from(mip.decompressed_size)
            })
    }
}

/// A parsed entry: its header, and the table saying where its blocks are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    offset: u64,
    header: EntryHeader,
    body: EntryBody,
}

/// The type-specific half of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryBody {
    /// A placeholder with no data.
    Empty,
    /// A block table, in data-region order.
    Standard(Vec<StandardBlock>),
    /// One descriptor per mip level.
    Texture(TextureTable),
    /// The model format's section table. Boxed: it is an order of magnitude larger than the other
    /// arms and would otherwise set the size of every entry.
    Model(Box<ModelTable>),
    /// A content type outside the known set: nothing was interpreted.
    Unknown,
}

impl Entry {
    /// Parse an entry from its header region, which must be at least the declared header length.
    ///
    /// `offset` is where the entry sits in its dat file, and is what the returned errors and block
    /// positions are measured against.
    ///
    /// # Errors
    /// - [`Error::Truncated`] if `buf` is shorter than the header declares, or than its table needs.
    /// - [`Error::LimitExceeded`] if the header or the declared file size exceeds `limits`.
    /// - [`Error::EntryCorrupt`] if the table does not fit inside the declared header.
    pub fn parse(buf: &[u8], offset: u64, limits: &DatLimits) -> Result<Self> {
        let header = parse_entry_header(buf, offset, limits)?;
        let declared = usize::try_from(header.header_size).map_err(|_| Error::LimitExceeded)?;
        let head = buf.get(..declared).ok_or_else(|| Error::Truncated {
            offset: offset.saturating_add(buf.len() as u64),
            needed: (declared - buf.len()) as u64,
        })?;

        let body = match header.content_type {
            // An empty entry's remaining words describe nothing, so nothing reads them.
            ContentType::Empty => EntryBody::Empty,
            ContentType::Standard => EntryBody::Standard(parse_standard(head, offset)?),
            ContentType::Texture => EntryBody::Texture(parse_texture(head, offset)?),
            ContentType::Model => EntryBody::Model(Box::new(ModelTable::parse(head, offset)?)),
            ContentType::Unknown(_) => EntryBody::Unknown,
        };
        Ok(Self {
            offset,
            header,
            body,
        })
    }

    /// Where the entry sits in its dat file.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The entry's header words.
    #[must_use]
    pub fn header(&self) -> &EntryHeader {
        &self.header
    }

    /// What kind of content the entry holds.
    #[must_use]
    pub fn content_type(&self) -> ContentType {
        self.header.content_type
    }

    /// The type-specific table.
    #[must_use]
    pub fn body(&self) -> &EntryBody {
        &self.body
    }

    /// Where the entry's data region starts in its dat file.
    #[must_use]
    pub fn data_offset(&self) -> u64 {
        self.offset
            .saturating_add(u64::from(self.header.header_size))
    }

    /// The file length the entry declares.
    #[must_use]
    pub fn declared_len(&self) -> u64 {
        u64::from(self.header.raw_size)
    }

    /// What an extraction will produce, when the entry's own table says so.
    ///
    /// `None` twice, for opposite reasons: a model's table records only on-disk block sizes, so its
    /// extracted length is known once its blocks are decoded (and is always the declared one), while
    /// a content type this crate does not read will never extract at all. For everything else this is
    /// the declared length, except for a handful of volume textures whose declared length counts
    /// padding between mip surfaces that the archive does not store (see [`super::Dat::read_into`]).
    #[must_use]
    pub fn stored_len(&self) -> Option<u64> {
        match &self.body {
            EntryBody::Empty => Some(0),
            EntryBody::Standard(blocks) => Some(
                blocks
                    .iter()
                    .map(|b| u64::from(b.decompressed_size))
                    .sum::<u64>(),
            ),
            EntryBody::Texture(table) => Some(table.stored_len()),
            EntryBody::Model(_) | EntryBody::Unknown => None,
        }
    }

    /// How many blocks the entry's data region holds.
    #[must_use]
    pub fn block_count(&self) -> usize {
        match &self.body {
            EntryBody::Empty | EntryBody::Unknown => 0,
            EntryBody::Standard(blocks) => blocks.len(),
            EntryBody::Texture(table) => table.block_sizes.len(),
            EntryBody::Model(model) => model.block_sizes.len(),
        }
    }
}

/// Parse the five words every entry header opens with, bounded by `limits`.
fn parse_entry_header(buf: &[u8], offset: u64, limits: &DatLimits) -> Result<EntryHeader> {
    let mut c = Cursor::new(buf, offset);
    let header_size = c.u32_le()?;
    let content_type = ContentType::from_word(c.u32_le()?);
    let raw_size = c.u32_le()?;
    let allocated_units = c.u32_le()?;
    let occupied_units = c.u32_le()?;

    if header_size > limits.max_entry_header_bytes {
        return Err(Error::LimitExceeded);
    }
    if header_size < ENTRY_HEADER_LEN as u32 {
        return Err(Error::EntryCorrupt {
            offset,
            detail: "entry header is shorter than its own fields",
        });
    }
    // An empty entry's size word is a leftover, so only a real one is held to the cap.
    if content_type != ContentType::Empty && u64::from(raw_size) > limits.max_file_bytes {
        return Err(Error::LimitExceeded);
    }
    Ok(EntryHeader {
        header_size,
        content_type,
        raw_size,
        allocated_units,
        occupied_units,
    })
}

/// The bytes a table of `count` records of `unit` bytes needs after `start`, refused when it does
/// not fit inside the declared header. The header is what bounds every table read, which is what
/// keeps a fabricated record count from reserving anything.
fn table(head: &[u8], start: usize, count: u64, unit: usize, offset: u64) -> Result<&[u8]> {
    let len = count
        .checked_mul(unit as u64)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(Error::EntryCorrupt {
            offset,
            detail: "entry table extent overflows",
        })?;
    let end = start.checked_add(len).ok_or(Error::EntryCorrupt {
        offset,
        detail: "entry table extent overflows",
    })?;
    head.get(start..end).ok_or(Error::EntryCorrupt {
        offset,
        detail: "entry table does not fit inside the declared header",
    })
}

/// The word at `0x14`, which each content type spends differently: a block count for a standard
/// entry, a mip count for a texture, the model format's version for a model.
fn type_word(head: &[u8], offset: u64) -> Result<u32> {
    head.get(ENTRY_HEADER_LEN..ENTRY_HEADER_LEN + 4)
        .and_then(|word| <[u8; 4]>::try_from(word).ok())
        .map(crate::bytes::u32_le)
        .ok_or(Error::EntryCorrupt {
            offset,
            detail: "entry header is too short to hold a table",
        })
}

fn parse_standard(head: &[u8], offset: u64) -> Result<Vec<StandardBlock>> {
    let count = u64::from(type_word(head, offset)?);
    let rows = table(
        head,
        ENTRY_HEADER_LEN + 4,
        count,
        STANDARD_BLOCK_LEN,
        offset,
    )?;
    let mut c = Cursor::new(rows, offset.saturating_add(ENTRY_HEADER_LEN as u64 + 4));
    let mut out = Vec::with_capacity(rows.len() / STANDARD_BLOCK_LEN);
    while c.remaining() >= STANDARD_BLOCK_LEN {
        let block_offset = c.u32_le()?;
        let on_disk_size = c.u16_le()?;
        let decompressed_size = c.u16_le()?;
        out.push(StandardBlock {
            offset: block_offset,
            on_disk_size,
            decompressed_size,
        });
    }
    Ok(out)
}

fn parse_texture(head: &[u8], offset: u64) -> Result<TextureTable> {
    let mip_count = u64::from(type_word(head, offset)?);
    let rows = table(head, ENTRY_HEADER_LEN + 4, mip_count, MIP_LEVEL_LEN, offset)?;
    let mut c = Cursor::new(rows, offset.saturating_add(ENTRY_HEADER_LEN as u64 + 4));
    let mut mips = Vec::with_capacity(rows.len() / MIP_LEVEL_LEN);
    let mut blocks = 0u64;
    while c.remaining() >= MIP_LEVEL_LEN {
        let mip = MipLevel {
            offset: c.u32_le()?,
            on_disk_size: c.u32_le()?,
            decompressed_size: c.u32_le()?,
            first_block: c.u32_le()?,
            block_count: c.u32_le()?,
        };
        blocks += u64::from(mip.block_count);
        mips.push(mip);
    }

    let sizes_at = ENTRY_HEADER_LEN + 4 + rows.len();
    let raw = table(head, sizes_at, blocks, 2, offset)?;
    let mut c = Cursor::new(raw, offset.saturating_add(sizes_at as u64));
    let mut block_sizes = Vec::with_capacity(raw.len() / 2);
    while c.remaining() >= 2 {
        block_sizes.push(c.u16_le()?);
    }
    Ok(TextureTable { mips, block_sizes })
}

#[cfg(test)]
mod tests {
    use super::super::builder::{DatBuilder, EntrySpec};
    use super::super::{DATA_HEADER_LEN, DATA_HEADER_OFFSET};
    use super::*;

    fn entry_of(spec: EntrySpec) -> Entry {
        let mut b = DatBuilder::new();
        b.entry(spec);
        let bytes = b.bytes();
        let offset = DATA_HEADER_OFFSET + u64::from(DATA_HEADER_LEN);
        let at = usize::try_from(offset).unwrap();
        Entry::parse(&bytes[at..], offset, &DatLimits::default()).unwrap()
    }

    #[test]
    fn a_standard_entry_reads_its_block_table() {
        let entry = entry_of(EntrySpec::standard(vec![
            b"hello ".to_vec(),
            b"world".to_vec(),
        ]));
        assert_eq!(entry.content_type(), ContentType::Standard);
        assert_eq!(entry.declared_len(), 11);
        assert_eq!(entry.stored_len(), Some(11));
        assert_eq!(entry.block_count(), 2);
        let EntryBody::Standard(blocks) = entry.body() else {
            panic!("expected a standard body");
        };
        assert_eq!(blocks[0].offset, 0);
        assert_eq!(blocks[0].decompressed_size, 6);
        assert_eq!(blocks[1].offset, u32::from(blocks[0].on_disk_size));
    }

    #[test]
    fn an_empty_entry_carries_its_leftover_words_without_acting_on_them() {
        // A real install has empty entries whose size and block-count words still describe the slot's
        // previous occupant. Reading them would frame a table that is not there.
        let entry = entry_of(EntrySpec::empty_with_leftovers(83952, 453, 57472));
        assert_eq!(entry.content_type(), ContentType::Empty);
        assert_eq!(entry.header().raw_size, 83952);
        assert_eq!(entry.header().allocated_units, 453);
        assert_eq!(entry.block_count(), 0);
        assert_eq!(entry.stored_len(), Some(0));
        assert_eq!(entry.body(), &EntryBody::Empty);
    }

    #[test]
    fn an_unknown_content_type_is_carried_verbatim_and_interprets_nothing() {
        let entry = entry_of(EntrySpec::unknown_type(9));
        assert_eq!(entry.content_type(), ContentType::Unknown(9));
        assert_eq!(entry.content_type().word(), 9);
        assert_eq!(entry.body(), &EntryBody::Unknown);
        assert_eq!(entry.stored_len(), None);
    }

    #[test]
    fn a_header_shorter_than_its_own_fields_is_corrupt() {
        let mut head = vec![0u8; 64];
        head[0..4].copy_from_slice(&crate::bytes::write_u32_le(8));
        head[4..8].copy_from_slice(&crate::bytes::write_u32_le(2));
        assert!(matches!(
            Entry::parse(&head, 0x800, &DatLimits::default()),
            Err(Error::EntryCorrupt { detail, .. }) if detail == "entry header is shorter than its own fields"
        ));
    }

    #[test]
    fn a_block_table_that_does_not_fit_the_declared_header_is_corrupt() {
        // The header length is what bounds every table read, so a count that overruns it is refused
        // before anything is reserved for it.
        let mut head = vec![0u8; 128];
        head[0..4].copy_from_slice(&crate::bytes::write_u32_le(128));
        head[4..8].copy_from_slice(&crate::bytes::write_u32_le(2));
        head[ENTRY_HEADER_LEN..ENTRY_HEADER_LEN + 4]
            .copy_from_slice(&crate::bytes::write_u32_le(1_000_000));
        assert!(matches!(
            Entry::parse(&head, 0x800, &DatLimits::default()),
            Err(Error::EntryCorrupt { detail, .. })
                if detail == "entry table does not fit inside the declared header"
        ));
    }

    #[test]
    fn a_declared_header_longer_than_the_cap_is_refused_before_it_is_read() {
        let mut head = vec![0u8; 128];
        head[0..4].copy_from_slice(&crate::bytes::write_u32_le(u32::MAX));
        head[4..8].copy_from_slice(&crate::bytes::write_u32_le(2));
        assert!(matches!(
            Entry::parse(&head, 0x800, &DatLimits::default()),
            Err(Error::LimitExceeded)
        ));
    }

    #[test]
    fn a_declared_file_size_over_the_cap_is_refused() {
        let mut head = vec![0u8; 128];
        head[0..4].copy_from_slice(&crate::bytes::write_u32_le(128));
        head[4..8].copy_from_slice(&crate::bytes::write_u32_le(2));
        head[8..12].copy_from_slice(&crate::bytes::write_u32_le(u32::MAX));
        assert!(matches!(
            Entry::parse(&head, 0x800, &DatLimits::default()),
            Err(Error::LimitExceeded)
        ));
        // The same word on an empty entry is a leftover, so it is carried rather than refused.
        head[4..8].copy_from_slice(&crate::bytes::write_u32_le(1));
        assert!(Entry::parse(&head, 0x800, &DatLimits::default()).is_ok());
    }

    #[test]
    fn a_header_cut_short_of_its_declared_length_is_truncated() {
        let mut head = vec![0u8; 64];
        head[0..4].copy_from_slice(&crate::bytes::write_u32_le(128));
        head[4..8].copy_from_slice(&crate::bytes::write_u32_le(2));
        assert!(matches!(
            Entry::parse(&head, 0x800, &DatLimits::default()),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn an_offset_at_the_end_of_the_address_space_is_reported_rather_than_wrapped() {
        // `parse` takes the file position its caller found the entry at, and reports faults against
        // it. Nothing bounds that number, so the arithmetic that carries it has to saturate: wrapping
        // would abort a debug build instead of returning the truncation this is.
        let mut head = vec![0u8; 32];
        head[0..4].copy_from_slice(&crate::bytes::write_u32_le(128));
        head[4..8].copy_from_slice(&crate::bytes::write_u32_le(2));
        match Entry::parse(&head, u64::MAX - 8, &DatLimits::default()) {
            Err(Error::Truncated { offset, .. }) => assert_eq!(offset, u64::MAX),
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn the_slot_a_header_declares_is_its_header_plus_its_allocation() {
        let header = EntryHeader {
            header_size: 128,
            content_type: ContentType::Standard,
            raw_size: 1076,
            allocated_units: 7,
            occupied_units: 5,
        };
        assert_eq!(header.allocated_bytes(), 896);
        assert_eq!(header.occupied_bytes(), 640);
        assert_eq!(header.slot_len(), 1024);
    }
}
