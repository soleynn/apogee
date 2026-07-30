//! Dat containers: the archives an index points into, and the extraction that turns an entry back
//! into the file it holds.
//!
//! A `.dat` opens with the common header, then a data header at `0x400` describing the region after
//! it, then entries back to back from `0x800`. Nothing indexes the entries: an index resolves a path
//! to a byte offset and the entry starts there, which is why a sweep over a whole archive is the
//! inspector's job rather than something this module offers.
//!
//! **The common header is not always there.** Nineteen of the eighty-six dat files in a full retail
//! install carry no `SqPack` magic at all: their first twenty-four bytes are the same blob in every
//! one of them (`128, 0, 0, 15, 0, 2` as little-endian words, the shape a patcher's empty-block
//! marker has), the rest of the 1024 bytes is an ordinary header, and the SHA-1 the header carries
//! at `0x3C0` matches those bytes rather than a magic that was overwritten. Every one is a spanned
//! file (`dat1` and up, never `dat0`), each declares a data header and a data region that match its
//! length exactly, and their entries read like any other. So a missing common header is recorded and
//! carried, never a refusal: refusing would make a fifth of a real install unreadable.
//!
//! The same marker fills the space between entries. A patch that deletes or moves a file leaves its
//! slot behind, zeroed with a 24-byte header at the front saying how many blocks the run covers:
//! [`empty_block_header`] writes it, [`empty_block_count`] reads it back, and a stretch of a data
//! region no entry claims is a chain of them.
//!
//! ```no_run
//! use apogee_sqpack::{Dat, GameData};
//! let game = GameData::open("/path/to/game")?;
//! if let Some(found) = game.lookup("exd/root.exl")? {
//!     let dat = Dat::open(&found.dat_path)?;
//!     let entry = dat.entry_at(found.offset)?;
//!     let bytes = dat.read(&entry)?;
//!     assert_eq!(bytes.len() as u64, entry.declared_len());
//! }
//! # Ok::<(), apogee_sqpack::Error>(())
//! ```

mod empty;
mod entry;
mod model;
mod source;

#[cfg(any(test, feature = "test-fixtures"))]
pub(crate) mod builder;

use std::io::Write;
use std::path::Path;

use crate::bytes::Cursor;
use crate::codec::{self, BlockMeta};
use crate::container::{COMMON_HEADER_LEN, CommonHeader, parse_common_header};
use crate::error::{Error, Result};

pub use empty::{EMPTY_BLOCK_HEADER_LEN, empty_block_count, empty_block_header};
pub use entry::{
    ContentType, DATA_UNIT, DEFAULT_MAX_ENTRY_HEADER_BYTES, DEFAULT_MAX_FILE_BYTES, DatLimits,
    ENTRY_HEADER_LEN, Entry, EntryBody, EntryHeader, MIP_LEVEL_LEN, MipLevel, STANDARD_BLOCK_LEN,
    StandardBlock, TextureTable,
};
pub use model::{
    BlockRun, MODEL_FILE_HEADER_LEN, MODEL_LOD_COUNT, MODEL_TABLE_OFFSET, ModelSection, ModelTable,
};
pub use source::{DatSource, FileSource};

use source::Window;

/// Where a dat container's second header starts: immediately after the common header.
pub const DATA_HEADER_OFFSET: u64 = COMMON_HEADER_LEN as u64;

/// The declared length of the data header, and so the offset of the first entry.
pub const DATA_HEADER_LEN: u32 = 0x400;

/// Where the data region starts, and so the lowest offset any entry can sit at.
pub(crate) const DATA_REGION_OFFSET: u64 = DATA_HEADER_OFFSET + DATA_HEADER_LEN as u64;

/// Where the data header declares its own length: the position [`parse_data_header`] reads it from.
pub(crate) const DATA_HEADER_SIZE_AT: u64 = DATA_HEADER_OFFSET;

/// Where the data header carries the word whose role is not settled and whose value never varies.
pub(crate) const DATA_UNCLASSIFIED_AT: u64 = DATA_HEADER_OFFSET + 0x08;

/// Where the data header declares the length of the region after it.
pub(crate) const DATA_UNITS_AT: u64 = DATA_HEADER_OFFSET + 0x0C;

/// The three words the data header reserves, in the order [`parse_data_header`] skips them. Zero in
/// every dat file of an install, and addressed here because a check that names one has to say where
/// it is.
pub(crate) const DATA_RESERVED_AT: [u64; 3] = [
    DATA_HEADER_OFFSET + 0x04,
    DATA_HEADER_OFFSET + 0x14,
    DATA_HEADER_OFFSET + 0x1C,
];

/// How much of an extraction to reserve up front. The rest grows as bytes arrive, so an entry that
/// declares a size nothing backs cannot make a reservation out of it.
const READ_RESERVE_HINT: u64 = 1 << 20;

/// The data header at `0x400`, describing the region the entries live in.
///
/// `data_size` is the only field an extraction needs; the rest are carried for the inspector. The
/// SHA-1 covers the whole data region and is deliberately not checked on open: hashing seven
/// gigabytes to read one file would be absurd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    /// The declared header length (expected [`DATA_HEADER_LEN`]), recorded as read.
    pub header_size: u32,
    /// A word that is 16 in every dat file of a full install and whose role is not settled.
    pub unclassified: u32,
    /// The data region's length, in 128-byte units.
    pub data_units: u32,
    /// Which of the archive's dat files this is, as the container spells it. A full install spells
    /// `dat0` and `dat1` both as 1 in places, so it is carried rather than trusted.
    pub span_index: u32,
    /// The length at which the archive rolls over to the next dat file (two billion bytes in every
    /// dat of a full install but one, an empty archive declaring a tenth of that).
    pub max_file_size: u32,
    /// The SHA-1 the header claims over the data region.
    pub data_sha1: [u8; 20],
}

impl DataHeader {
    /// The data region's length in bytes.
    #[must_use]
    pub fn data_size(&self) -> u64 {
        u64::from(self.data_units) * u64::from(DATA_UNIT)
    }

    /// The container length the header implies: both headers plus the data region.
    #[must_use]
    pub fn declared_file_len(&self) -> u64 {
        DATA_HEADER_OFFSET + u64::from(DATA_HEADER_LEN) + self.data_size()
    }
}

/// An open dat container.
///
/// Reads carry their own offset, so one open container answers several callers at once and a handle
/// is `Send + Sync` over immutable state.
///
/// A handle is not the snapshot an [`crate::Index`] is: the two headers and the length are read once
/// at open, while every entry is read from the file as it is asked for. So a caller that patches or
/// repairs while holding one gets a mixture of vintages, not a stale-but-consistent view, and has to
/// open a fresh handle.
#[derive(Debug)]
pub struct Dat<S = FileSource> {
    source: S,
    common: Option<CommonHeader>,
    data: DataHeader,
    limits: DatLimits,
}

impl Dat<FileSource> {
    /// Open a dat container and parse its two headers.
    ///
    /// # Errors
    /// - [`Error::Io`] if the file cannot be opened.
    /// - Everything [`Dat::from_source`] raises.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_limits(path, &DatLimits::default())
    }

    /// Open a dat container under caller-chosen bounds.
    ///
    /// # Errors
    /// The same faults [`Dat::open`] raises.
    pub fn open_with_limits(path: impl AsRef<Path>, limits: &DatLimits) -> Result<Self> {
        Self::from_source(FileSource::open(path)?, limits)
    }
}

impl<'a> Dat<&'a [u8]> {
    /// Read a dat container that is already in memory. This is what tests and the fuzzer drive; a
    /// real archive is far too large to hold.
    ///
    /// # Errors
    /// Everything [`Dat::from_source`] raises.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        Self::from_source(buf, &DatLimits::default())
    }
}

impl<S: DatSource> Dat<S> {
    /// Parse the two headers of a container from any source.
    ///
    /// A container with no `SqPack` magic is opened anyway, with no common header (see this module's
    /// note); one that has a header declaring some other kind of container is refused, since that is
    /// a file which says what it is and is not this.
    ///
    /// # Errors
    /// - [`Error::UnsupportedPlatform`] if a common header names a platform outside the known set.
    /// - [`Error::Truncated`] if the container ends inside the data header.
    /// - [`Error::EntryCorrupt`] if a common header declares something other than a dat file.
    pub fn from_source(source: S, limits: &DatLimits) -> Result<Self> {
        let mut head = [0u8; COMMON_HEADER_LEN];
        let read = source.read_at(&mut head, 0)?;
        let common = match parse_common_header(&head[..read]) {
            Ok(common) => Some(common),
            Err(Error::BadMagic) => None,
            Err(err) => return Err(err),
        };
        if common.is_some_and(|c| c.kind != crate::container::SqPackKind::Data) {
            return Err(Error::EntryCorrupt {
                offset: 0x14,
                detail: "not a dat container",
            });
        }
        let mut second = [0u8; 0x34];
        source.read_exact_at(&mut second, DATA_HEADER_OFFSET)?;
        let data = parse_data_header(&second, DATA_HEADER_OFFSET)?;
        Ok(Self {
            source,
            common,
            data,
            limits: *limits,
        })
    }

    /// The container's common header, or `None` for one of the spanned dat files that carry no
    /// `SqPack` magic (this module's note).
    #[must_use]
    pub fn common_header(&self) -> Option<&CommonHeader> {
        self.common.as_ref()
    }

    /// The container's data header.
    #[must_use]
    pub fn data_header(&self) -> &DataHeader {
        &self.data
    }

    /// The container's length on disk.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.source.len()
    }

    /// Whether the container holds no bytes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.source.is_empty()
    }

    /// The bytes behind the container, for the checks that read spans no entry frames: the two
    /// headers, the data region as one run, and the space between slots.
    pub(crate) fn source(&self) -> &S {
        &self.source
    }

    /// The bounds this container reads under.
    #[must_use]
    pub fn limits(&self) -> &DatLimits {
        &self.limits
    }

    /// Parse the entry at `offset`, which is what an index resolves a path to.
    ///
    /// # Errors
    /// - [`Error::Truncated`] if the container ends inside the entry's header.
    /// - Everything [`Entry::parse`] raises.
    pub fn entry_at(&self, offset: u64) -> Result<Entry> {
        let mut lead = [0u8; ENTRY_HEADER_LEN];
        self.source.read_exact_at(&mut lead, offset)?;
        let header_size = crate::bytes::read_u32_le(&lead, 0);
        if header_size > self.limits.max_entry_header_bytes {
            return Err(Error::LimitExceeded);
        }
        // Reserved for the header the entry declares, but never for more than the container has left
        // to give: a declared length nothing backs then reads short and is a truncation, rather than
        // a megabyte reserved on the strength of four bytes.
        let available = self.source.len().saturating_sub(offset);
        let len = usize::try_from(u64::from(header_size).min(available))
            .map_err(|_| Error::LimitExceeded)?;
        let mut head = vec![0u8; len.max(ENTRY_HEADER_LEN)];
        self.source.read_exact_at(&mut head, offset)?;
        Entry::parse(&head, offset, &self.limits)
    }

    /// The five words at `offset`, which is what a slot walk needs: reads exactly
    /// [`ENTRY_HEADER_LEN`] bytes, where [`Dat::entry_at`] reads the whole declared header so it can
    /// frame the tables too.
    ///
    /// # Errors
    /// - [`Error::Truncated`] if the container ends inside those five words.
    /// - Everything [`EntryHeader::parse`] raises.
    pub fn entry_header_at(&self, offset: u64) -> Result<EntryHeader> {
        let mut lead = [0u8; ENTRY_HEADER_LEN];
        self.source.read_exact_at(&mut lead, offset)?;
        EntryHeader::parse(&lead, offset, &self.limits)
    }

    /// The entry at `offset`, extracted. Named apart from [`DatSource::read_at`], which hands back
    /// the container's bytes as they sit rather than the file an entry holds.
    ///
    /// # Errors
    /// Everything [`Dat::entry_at`] and [`Dat::read`] raise.
    pub fn read_entry_at(&self, offset: u64) -> Result<Vec<u8>> {
        let entry = self.entry_at(offset)?;
        self.read(&entry)
    }

    /// Extract an entry into a fresh buffer. The entry has to be one this container parsed: an
    /// [`Entry`] carries the offset it was read from and nothing that ties it to a file, so reading
    /// one against another container would decode whatever sits at that offset there.
    ///
    /// # Errors
    /// Everything [`Dat::read_into`] raises.
    pub fn read(&self, entry: &Entry) -> Result<Vec<u8>> {
        // Reserved from what the entry declares, but only up to a fixed hint: the rest grows as
        // bytes arrive, so a fabricated size cannot make a reservation out of a number nobody has
        // read yet.
        let hint = entry.declared_len().min(READ_RESERVE_HINT);
        let mut out = Vec::with_capacity(usize::try_from(hint).unwrap_or(0));
        self.read_into(entry, &mut out)?;
        Ok(out)
    }

    /// Extract an entry into `out`, returning how many bytes it wrote.
    ///
    /// The result is the bytes the archive holds, decoded block by block, and it is the size the
    /// entry declares except for one case: a few hundred volume textures out of the four hundred
    /// thousand in a full install declare a length that counts padding between mip surfaces which the
    /// archive does not store, so extracting one of those is short of the declared size by that
    /// padding. [`Entry::stored_len`] says so before the read, and nothing is invented to close the
    /// gap.
    ///
    /// On failure `out` may already hold a prefix of the file: blocks are written as they decode, so
    /// a fault partway through leaves what came before it. (The model arm is the exception, since a
    /// model's header cannot be written until its sections are known, so it emits nothing at all.) A
    /// caller that cannot tolerate a partial file writes into a buffer, or into a file it discards on
    /// error.
    ///
    /// # Errors
    /// - [`Error::EntryCorrupt`] if the entry's content type is not one this crate reads, if a block
    ///   decodes to a different size or occupies different space than its table declares, if a table
    ///   names blocks the entry does not hold, or if the whole extraction comes out a different
    ///   length than the entry declares.
    /// - [`Error::BlockCorrupt`] / [`Error::Truncated`] from the codec, rebased onto the container.
    /// - [`Error::LimitExceeded`] if a block decodes past the caller's bounds.
    /// - [`Error::Io`] if `out` fails to accept the bytes.
    pub fn read_into(&self, entry: &Entry, out: &mut impl Write) -> Result<u64> {
        let mut run = Extraction {
            base: entry.data_offset(),
            // Nothing an entry holds sits outside the slot it declares, so that is where its reads
            // stop: a block table that points past it is naming another entry's bytes, and answering
            // with those would be handing back the wrong file rather than reporting a broken one.
            end: entry
                .data_offset()
                .saturating_add(entry.header().allocated_bytes())
                .min(self.source.len()),
            spent: 0,
            limit: entry.declared_len(),
            offset: entry.offset(),
        };
        let written = match entry.body() {
            EntryBody::Empty => 0,
            EntryBody::Unknown => {
                return Err(Error::EntryCorrupt {
                    offset: entry.offset(),
                    detail: "entry content type is not one this crate reads",
                });
            }
            EntryBody::Standard(blocks) => self.read_standard(blocks, out, &mut run)?,
            EntryBody::Texture(table) => self.read_texture(entry, table, out, &mut run)?,
            EntryBody::Model(table) => self.read_model(entry, table, out, &mut run)?,
        };
        // Coming out short is as wrong as coming out long: the declared size is what a caller
        // reserves for the file. Two content types are exempt because their declared word is not a
        // length: an empty entry's is its slot's previous occupant's leftover, and a texture's counts
        // the mip-surface padding above.
        if matches!(
            entry.content_type(),
            ContentType::Standard | ContentType::Model
        ) && written != entry.declared_len()
        {
            return Err(Error::EntryCorrupt {
                offset: entry.offset(),
                detail: "entry decoded to a different length than it declares",
            });
        }
        Ok(written)
    }

    /// Decode one block at an absolute container offset, rebasing the codec's block-relative faults
    /// onto the container so triage points at the file.
    fn decode_block(&self, at: u64, end: u64, out: &mut impl Write) -> Result<BlockMeta> {
        let mut window = Window::new(&self.source, at, end);
        codec::read_block(&mut window, out, &self.limits.block).map_err(|err| rebase(err, at))
    }

    /// Decode one block, holding it to the on-disk size its entry declares (which is what the next
    /// block's position is measured from) and to what is left of the entry's budget.
    fn decode_sized(
        &self,
        at: u64,
        on_disk: u32,
        out: &mut impl Write,
        run: &mut Extraction,
    ) -> Result<u64> {
        let meta = self.decode_block(at, run.end, out)?;
        if meta.block_len != on_disk {
            return Err(Error::EntryCorrupt {
                offset: at,
                detail: "block does not occupy the space its entry declares",
            });
        }
        run.spend(u64::from(meta.decompressed_size))
    }

    /// Decode a run of blocks laid back to back from `at`, each as long as its table row says.
    fn decode_run(
        &self,
        at: u64,
        sizes: &[u16],
        out: &mut impl Write,
        run: &mut Extraction,
    ) -> Result<u64> {
        let mut at = at;
        let mut produced = 0u64;
        for size in sizes {
            produced += self.decode_sized(at, u32::from(*size), out, run)?;
            at = at.saturating_add(u64::from(*size));
        }
        Ok(produced)
    }

    fn read_standard(
        &self,
        blocks: &[StandardBlock],
        out: &mut impl Write,
        run: &mut Extraction,
    ) -> Result<u64> {
        let mut written = 0u64;
        for block in blocks {
            let at = run.base.saturating_add(u64::from(block.offset));
            let produced = self.decode_sized(at, u32::from(block.on_disk_size), out, run)?;
            if produced != u64::from(block.decompressed_size) {
                return Err(Error::EntryCorrupt {
                    offset: at,
                    detail: "block decoded to a different size than its entry declares",
                });
            }
            written += produced;
        }
        Ok(written)
    }

    fn read_texture(
        &self,
        entry: &Entry,
        table: &TextureTable,
        out: &mut impl Write,
        run: &mut Extraction,
    ) -> Result<u64> {
        if table.mips.is_empty() && entry.declared_len() > 0 {
            return Err(Error::EntryCorrupt {
                offset: entry.offset(),
                detail: "texture entry declares a file but no mip levels",
            });
        }
        // The texture format's own header sits uncompressed at the front of the data region. It is
        // reserved only once the entry is known to hold that many bytes, so a fabricated first-mip
        // offset buys an error rather than a gigabyte.
        let head_len = u64::from(table.raw_header_len());
        if head_len > entry.declared_len() {
            return Err(Error::EntryCorrupt {
                offset: entry.offset(),
                detail: "texture header is longer than the file it belongs to",
            });
        }
        let room = run.end.saturating_sub(run.base);
        if head_len > room {
            return Err(Error::Truncated {
                offset: run.end,
                needed: head_len - room,
            });
        }
        let mut head = vec![0u8; usize::try_from(head_len).map_err(|_| Error::LimitExceeded)?];
        self.source.read_exact_at(&mut head, run.base)?;
        out.write_all(&head)?;
        let mut written = run.spend(head_len)?;

        for mip in &table.mips {
            let sizes = block_range(mip.first_block, mip.block_count, table.block_sizes.len())
                .map(|range| &table.block_sizes[range])
                .ok_or(Error::EntryCorrupt {
                    offset: entry.offset(),
                    detail: "a mip level names blocks the entry does not hold",
                })?;
            let produced = self.decode_run(
                run.base.saturating_add(u64::from(mip.offset)),
                sizes,
                out,
                run,
            )?;
            if produced != u64::from(mip.decompressed_size) {
                return Err(Error::EntryCorrupt {
                    offset: entry.offset(),
                    detail: "a mip level decoded to a different size than it declares",
                });
            }
            written += produced;
        }
        Ok(written)
    }

    fn read_model(
        &self,
        entry: &Entry,
        table: &ModelTable,
        out: &mut impl Write,
        run: &mut Extraction,
    ) -> Result<u64> {
        // A model's header cannot be written until its sections are decoded, since their lengths are
        // what it describes; the budget is what keeps the buffer from growing past the declared file.
        let head_len = run.spend(MODEL_FILE_HEADER_LEN as u64)?;
        let body_len = entry.declared_len() - head_len;
        let mut body =
            Vec::with_capacity(usize::try_from(body_len.min(READ_RESERVE_HINT)).unwrap_or(0));
        let mut lengths = [0u64; 2 + 3 * MODEL_LOD_COUNT];

        for (i, (_, section)) in table.sections().into_iter().enumerate() {
            let (start, sizes) = table.run_extent(section).ok_or(Error::EntryCorrupt {
                offset: entry.offset(),
                detail: "a model section names blocks the entry does not hold",
            })?;
            lengths[i] = self.decode_run(run.base.saturating_add(start), sizes, &mut body, run)?;
        }

        let head = table.file_header(&lengths);
        out.write_all(&head)?;
        out.write_all(&body)?;
        Ok(head_len + body.len() as u64)
    }
}

/// One entry's read: where its bytes are, and what is left of the size it declares.
///
/// Every offset built from `base` saturates. A [`DatSource`] is a public seam and its `len` is
/// whatever the implementor says, so a table word added to a base near the end of the address space
/// must come out as a read past the end (which is a truncation) rather than as an overflow.
///
/// A block is charged once it has decoded, so a fabricated table overruns by at most the one block
/// that broke the budget (itself capped by [`codec::Limits`]) before the read stops, rather than by
/// however many blocks the table names.
struct Extraction {
    /// Where the entry's data region starts.
    base: u64,
    /// One past the last byte the entry's slot covers.
    end: u64,
    spent: u64,
    limit: u64,
    offset: u64,
}

impl Extraction {
    /// Charge `n` bytes, returning them, or fail once the entry has produced more than it declares.
    fn spend(&mut self, n: u64) -> Result<u64> {
        self.spent = self.spent.saturating_add(n);
        if self.spent > self.limit {
            return Err(Error::EntryCorrupt {
                offset: self.offset,
                detail: "entry decoded to more bytes than it declares",
            });
        }
        Ok(n)
    }
}

/// The block indexes a run covers, or `None` if it names one the entry does not hold.
fn block_range(first: u32, count: u32, total: usize) -> Option<std::ops::Range<usize>> {
    let start = usize::try_from(first).ok()?;
    let end = start.checked_add(usize::try_from(count).ok()?)?;
    (end <= total).then_some(start..end)
}

/// Move a codec fault from block-relative to container-absolute.
fn rebase(err: Error, at: u64) -> Error {
    match err {
        Error::BlockCorrupt { offset, detail } => Error::BlockCorrupt {
            offset: at.saturating_add(offset),
            detail,
        },
        Error::Truncated { offset, needed } => Error::Truncated {
            offset: at.saturating_add(offset),
            needed,
        },
        other => other,
    }
}

/// Parse the data header at `0x400`.
fn parse_data_header(buf: &[u8], offset: u64) -> Result<DataHeader> {
    let mut c = Cursor::new(buf, offset);
    let header_size = c.u32_le()?;
    c.skip(4)?; // reserved
    let unclassified = c.u32_le()?;
    let data_units = c.u32_le()?;
    let span_index = c.u32_le()?;
    c.skip(4)?; // reserved
    let max_file_size = c.u32_le()?;
    c.skip(4)?; // reserved
    let raw = c.take(20)?;
    let data_sha1 = <[u8; 20]>::try_from(raw).map_err(|_| Error::EntryCorrupt {
        offset: c.offset(),
        detail: "array conversion",
    })?;
    Ok(DataHeader {
        header_size,
        unclassified,
        data_units,
        span_index,
        max_file_size,
        data_sha1,
    })
}

#[cfg(test)]
mod tests {
    use super::builder::{DatBuilder, EntrySpec, Packing, block_bytes};
    use super::*;
    use crate::bytes;

    /// A container holding one entry, with the entry and the content it should extract to.
    fn one(spec: EntrySpec) -> (Vec<u8>, u64, Vec<u8>) {
        let mut b = DatBuilder::new();
        b.entry(spec);
        let (bytes, placed) = b.build();
        (bytes, placed[0].offset, placed[0].content.clone())
    }

    fn extract(bytes: &[u8], offset: u64) -> Result<Vec<u8>> {
        let dat = Dat::parse(bytes)?;
        let entry = dat.entry_at(offset)?;
        dat.read(&entry)
    }

    #[test]
    fn a_standard_entry_round_trips_through_the_reader() {
        let chunks = vec![
            b"the quick brown fox ".repeat(40),
            b"jumps over the lazy dog".to_vec(),
        ];
        let (bytes, offset, content) = one(EntrySpec::standard(chunks));
        let dat = Dat::parse(&bytes).unwrap();
        let entry = dat.entry_at(offset).unwrap();
        assert_eq!(entry.content_type(), ContentType::Standard);
        assert_eq!(entry.block_count(), 2);
        assert_eq!(entry.declared_len(), content.len() as u64);
        assert_eq!(entry.stored_len(), Some(content.len() as u64));
        assert_eq!(dat.read(&entry).unwrap(), content);
        // The convenience path takes the offset an index resolved and answers the same bytes.
        assert_eq!(dat.read_entry_at(offset).unwrap(), content);
    }

    #[test]
    fn a_stored_block_reads_the_same_as_a_compressed_one() {
        // Incompressible content is stored verbatim behind the sentinel; the entry above it is
        // identical either way.
        let chunk: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let (bytes, offset, content) = one(EntrySpec::standard_stored(vec![chunk]));
        assert_eq!(extract(&bytes, offset).unwrap(), content);
    }

    #[test]
    fn an_empty_entry_extracts_nothing() {
        let (bytes, offset, _) = one(EntrySpec::empty_with_leftovers(83952, 453, 57472));
        let dat = Dat::parse(&bytes).unwrap();
        let entry = dat.entry_at(offset).unwrap();
        assert_eq!(entry.content_type(), ContentType::Empty);
        assert!(dat.read(&entry).unwrap().is_empty());
    }

    #[test]
    fn a_texture_entry_keeps_its_uncompressed_header_and_every_mip() {
        let header = vec![0xABu8; 80];
        let mips = vec![vec![1u8; 4096], vec![2u8; 1024], vec![3u8; 256]];
        let (bytes, offset, content) = one(EntrySpec::texture(header, mips));
        let dat = Dat::parse(&bytes).unwrap();
        let entry = dat.entry_at(offset).unwrap();
        assert_eq!(entry.content_type(), ContentType::Texture);
        let EntryBody::Texture(table) = entry.body() else {
            panic!("expected a texture body");
        };
        assert_eq!(table.raw_header_len(), 80);
        assert_eq!(table.mips.len(), 3);
        assert_eq!(entry.stored_len(), Some(80 + 4096 + 1024 + 256));
        assert_eq!(dat.read(&entry).unwrap(), content);
    }

    #[test]
    fn a_model_entry_puts_back_the_header_the_packer_folded_away() {
        // The 68 bytes a model file opens with are not stored anywhere: they are rebuilt from the
        // entry header, with the offsets recomputed from what the sections actually decode to.
        let sections = [
            b"stack".repeat(100),
            b"runtime".repeat(200),
            b"vertex0".repeat(300),
            Vec::new(),
            b"index0".repeat(50),
            b"vertex1".repeat(30),
            Vec::new(),
            b"index1".repeat(10),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ];
        let (bytes, offset, content) = one(EntrySpec::model(sections));
        let dat = Dat::parse(&bytes).unwrap();
        let entry = dat.entry_at(offset).unwrap();
        assert_eq!(entry.content_type(), ContentType::Model);
        // A model's extracted length is known only once its blocks are decoded.
        assert_eq!(entry.stored_len(), None);
        let out = dat.read(&entry).unwrap();
        assert_eq!(out, content);
        assert_eq!(out.len() as u64, entry.declared_len());
        let word = |at: usize| bytes::read_u32_le(&out, at);
        assert_eq!(word(0x00), 0x0100_0006); // the format version, carried through
        assert_eq!(word(0x04), 500); // the stack section, as decoded
        assert_eq!(word(0x10), 68 + 500 + 1400); // the first vertex buffer
        assert_eq!(word(0x18), 0); // a level of detail with nothing in it
        assert_eq!(out[0x40], 3);
    }

    #[test]
    fn the_slack_an_archive_reserves_does_not_change_what_is_read() {
        // An archive that shrank a file in place keeps the rest of the slot reserved, so the entry
        // occupies more than it stores. Extraction is driven by the tables, not by the slot.
        let mut b = DatBuilder::new();
        b.slack(4)
            .entry(EntrySpec::standard(vec![b"first".to_vec()]));
        b.entry(EntrySpec::standard(vec![b"second".to_vec()]));
        let (bytes, placed) = b.build();
        let dat = Dat::parse(&bytes).unwrap();
        for at in &placed {
            let entry = dat.entry_at(at.offset).unwrap();
            assert_eq!(dat.read(&entry).unwrap(), at.content);
            assert!(entry.header().allocated_units > entry.header().occupied_units);
            assert_eq!(
                entry.header().slot_len(),
                u64::from(entry.header().header_size) + entry.header().allocated_bytes()
            );
        }
        // The second entry starts exactly one slot past the first.
        let first = dat.entry_at(placed[0].offset).unwrap();
        assert_eq!(
            placed[0].offset + first.header().slot_len(),
            placed[1].offset
        );
    }

    #[test]
    fn a_slot_walk_reads_five_words_where_a_full_parse_reads_a_whole_table() {
        // A sweep over an archive reads one of these at every location an index names, so it must
        // agree with the full parse on every word and must not depend on the table fitting.
        let mut b = DatBuilder::new();
        b.entry(EntrySpec::standard(vec![b"payload".repeat(400)]));
        let (bytes, placed) = b.build();
        let dat = Dat::parse(&bytes).unwrap();
        let offset = placed[0].offset;
        assert_eq!(
            dat.entry_header_at(offset).unwrap(),
            *dat.entry_at(offset).unwrap().header()
        );
        // Only the five words are read, so a container that ends right after them still answers.
        let short = &bytes[..usize::try_from(offset).unwrap() + ENTRY_HEADER_LEN];
        assert_eq!(
            Dat::from_source(short, &DatLimits::default())
                .unwrap()
                .entry_header_at(offset)
                .unwrap()
                .content_type,
            ContentType::Standard
        );
        assert!(matches!(
            dat.entry_header_at(bytes.len() as u64 - 4),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn the_data_header_describes_the_region_the_entries_live_in() {
        let (bytes, _, _) = one(EntrySpec::standard(vec![b"payload".to_vec()]));
        let dat = Dat::parse(&bytes).unwrap();
        let header = dat.data_header();
        assert_eq!(header.header_size, DATA_HEADER_LEN);
        assert_eq!(header.unclassified, 16);
        assert_eq!(header.max_file_size, 2_000_000_000);
        assert_eq!(header.declared_file_len(), bytes.len() as u64);
        assert_eq!(dat.len(), bytes.len() as u64);
        assert!(!dat.is_empty());
        assert_eq!(
            dat.common_header().map(|c| c.kind),
            Some(crate::SqPackKind::Data)
        );
    }

    // --- hostile input: every fault is a typed error at an offset, never a panic ---

    #[test]
    fn an_index_container_is_not_a_dat() {
        let mut b = DatBuilder::new();
        b.container_kind(2)
            .entry(EntrySpec::standard(vec![b"x".to_vec()]));
        match Dat::parse(&b.bytes()) {
            Err(Error::EntryCorrupt { offset, detail }) => {
                assert_eq!(offset, 0x14);
                assert_eq!(detail, "not a dat container");
            }
            other => panic!("expected EntryCorrupt, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn an_unknown_content_type_is_read_as_nothing_rather_than_guessed() {
        let (bytes, offset, _) = one(EntrySpec::unknown_type(9));
        assert!(matches!(
            extract(&bytes, offset),
            Err(Error::EntryCorrupt { detail, .. })
                if detail == "entry content type is not one this crate reads"
        ));
    }

    #[test]
    fn a_block_that_decodes_to_a_different_size_than_its_table_says_is_corrupt() {
        let (mut bytes, offset, _) =
            one(EntrySpec::standard(vec![b"the quick brown fox".to_vec()]));
        // Rewrite the block table's decompressed size, leaving the block itself alone.
        let at = usize::try_from(offset).unwrap() + ENTRY_HEADER_LEN + 4 + 6;
        bytes[at..at + 2].copy_from_slice(&bytes::write_u16_le(11));
        assert!(matches!(
            extract(&bytes, offset),
            Err(Error::EntryCorrupt { detail, .. })
                if detail == "block decoded to a different size than its entry declares"
        ));
    }

    #[test]
    fn a_block_that_does_not_occupy_the_space_its_table_reserves_is_corrupt() {
        let (mut bytes, offset, _) =
            one(EntrySpec::standard(vec![b"the quick brown fox".to_vec()]));
        let at = usize::try_from(offset).unwrap() + ENTRY_HEADER_LEN + 4 + 4;
        bytes[at..at + 2].copy_from_slice(&bytes::write_u16_le(256));
        assert!(matches!(
            extract(&bytes, offset),
            Err(Error::EntryCorrupt { detail, .. })
                if detail == "block does not occupy the space its entry declares"
        ));
    }

    #[test]
    fn a_block_fault_is_reported_where_it_sits_in_the_container() {
        // The codec measures faults from the block it was handed; the container rebases them, so
        // triage points at a byte in the dat file rather than at byte 8 of nothing in particular.
        let (mut bytes, offset, _) =
            one(EntrySpec::standard(vec![b"the quick brown fox".to_vec()]));
        let block_at = usize::try_from(offset).unwrap() + 128;
        // A "compressed" size above the stored sentinel is a framing the codec refuses outright.
        bytes[block_at + 8..block_at + 12].copy_from_slice(&bytes::write_u32_le(0x8000));
        match extract(&bytes, offset) {
            Err(Error::BlockCorrupt { offset: at, .. }) => {
                assert_eq!(at, block_at as u64 + 8);
            }
            other => panic!("expected BlockCorrupt, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn a_mip_level_naming_blocks_the_entry_does_not_hold_is_corrupt() {
        let (mut bytes, offset, _) = one(EntrySpec::texture(vec![0u8; 80], vec![vec![7u8; 64]]));
        // The mip starts past the end of the entry's block-size array, which holds one row.
        let at = usize::try_from(offset).unwrap() + ENTRY_HEADER_LEN + 4 + 12;
        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(1000));
        assert!(matches!(
            extract(&bytes, offset),
            Err(Error::EntryCorrupt { detail, .. })
                if detail == "a mip level names blocks the entry does not hold"
        ));
    }

    #[test]
    fn a_model_section_naming_blocks_the_entry_does_not_hold_is_corrupt() {
        let mut sections: [Vec<u8>; 11] = Default::default();
        sections[0] = b"stack".to_vec();
        sections[1] = b"runtime".to_vec();
        let (mut bytes, offset, _) = one(EntrySpec::model(sections));
        // The stack section starts past the end of the entry's block-size array, which holds two.
        let at = usize::try_from(offset).unwrap() + 0x9C;
        bytes[at..at + 2].copy_from_slice(&bytes::write_u16_le(5000));
        assert!(matches!(
            extract(&bytes, offset),
            Err(Error::EntryCorrupt { detail, .. })
                if detail == "a model section names blocks the entry does not hold"
        ));
    }

    #[test]
    fn an_entry_past_the_end_of_the_container_is_truncated() {
        let (bytes, _, _) = one(EntrySpec::standard(vec![b"payload".to_vec()]));
        let dat = Dat::parse(&bytes).unwrap();
        assert!(matches!(
            dat.entry_at(bytes.len() as u64 - 4),
            Err(Error::Truncated { .. })
        ));
        // An offset at the end of the address space is a truncation, not an overflow: nothing
        // bounds what a caller (or a rewritten index) hands over.
        for offset in [u64::MAX - 1, u64::MAX] {
            assert!(matches!(dat.entry_at(offset), Err(Error::Truncated { .. })));
        }
    }

    #[test]
    fn a_container_cut_short_of_its_data_header_is_truncated() {
        let (bytes, _, _) = one(EntrySpec::standard(vec![b"payload".to_vec()]));
        for cut in [0, 8, COMMON_HEADER_LEN, COMMON_HEADER_LEN + 0x10] {
            assert!(
                Dat::parse(&bytes[..cut]).is_err(),
                "a container cut at {cut} must not parse"
            );
        }
    }

    #[test]
    fn a_block_over_the_decompression_cap_is_refused() {
        let (bytes, offset, _) = one(EntrySpec::standard(vec![vec![9u8; 4096]]));
        let limits = DatLimits {
            block: crate::codec::Limits {
                max_decompressed: 64,
            },
            ..DatLimits::default()
        };
        let dat = Dat::from_source(&bytes[..], &limits).unwrap();
        let entry = dat.entry_at(offset).unwrap();
        assert!(matches!(dat.read(&entry), Err(Error::LimitExceeded)));
    }

    #[test]
    fn an_entry_that_decodes_past_what_it_declares_is_corrupt() {
        // The declared size is what a caller reserves for the file, so producing more than it is a
        // fault rather than a longer answer.
        let mut b = DatBuilder::new();
        b.entry(EntrySpec::standard(vec![b"0123456789".to_vec()]));
        let (mut bytes, placed) = b.build();
        let offset = placed[0].offset;
        let at = usize::try_from(offset).unwrap() + 8;
        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(4));
        assert!(matches!(
            extract(&bytes, offset),
            Err(Error::EntryCorrupt { detail, .. })
                if detail == "entry decoded to more bytes than it declares"
        ));
    }

    #[test]
    fn an_entry_that_decodes_short_of_what_it_declares_is_corrupt() {
        // Coming out short is as wrong as coming out long: a caller sizes the file from the declared
        // word, and the blocks are what has to fill it.
        let (mut bytes, offset, _) = one(EntrySpec::standard(vec![b"0123456789".to_vec()]));
        let at = usize::try_from(offset).unwrap() + 8;
        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(4096));
        assert!(matches!(
            extract(&bytes, offset),
            Err(Error::EntryCorrupt { detail, .. })
                if detail == "entry decoded to a different length than it declares"
        ));
    }

    #[test]
    fn a_block_outside_the_slot_the_entry_declares_is_not_read() {
        // Nothing an entry holds sits outside its slot, so a table pointing past it is naming the
        // next entry's bytes. Answering with those would hand back the wrong file.
        let mut b = DatBuilder::new();
        b.entry(EntrySpec::standard(vec![b"first entry".to_vec()]));
        b.entry(EntrySpec::standard(vec![b"second entry".to_vec()]));
        let (mut bytes, placed) = b.build();
        let first = usize::try_from(placed[0].offset).unwrap();
        // Point the first entry's only block at the second entry's block, one slot along.
        let block_at = u32::try_from(placed[1].offset - placed[0].offset).unwrap();
        bytes[first + ENTRY_HEADER_LEN + 4..first + ENTRY_HEADER_LEN + 8]
            .copy_from_slice(&bytes::write_u32_le(block_at));
        assert!(matches!(
            extract(&bytes, placed[0].offset),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn a_texture_header_longer_than_the_container_is_truncated_not_reserved() {
        // The header length is a word out of the file, so it is held to what the entry actually has
        // room for before a byte of it is reserved.
        let (mut bytes, offset, _) = one(EntrySpec::texture(vec![0u8; 80], vec![vec![7u8; 64]]));
        let at = usize::try_from(offset).unwrap();
        // A declared file large enough to clear the first check, and a first mip past the container.
        bytes[at + 8..at + 12].copy_from_slice(&bytes::write_u32_le(900_000));
        bytes[at + ENTRY_HEADER_LEN + 4..at + ENTRY_HEADER_LEN + 8]
            .copy_from_slice(&bytes::write_u32_le(800_000));
        assert!(matches!(
            extract(&bytes, offset),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn a_block_padded_to_a_whole_unit_leaves_the_next_one_where_the_table_says() {
        // A payload landing exactly on a 128-byte boundary has no padding at all, which is the case
        // most likely to slide the next block by a unit if the reader recomputed the length.
        let plain = vec![0xC3u8; 112];
        let block = block_bytes(&plain, Packing::Stored);
        assert_eq!(block.len(), 128);
        let (bytes, offset, content) = one(EntrySpec::standard_stored(vec![plain, vec![1u8; 8]]));
        assert_eq!(extract(&bytes, offset).unwrap(), content);
    }

    #[test]
    fn a_mip_spanning_several_blocks_walks_all_of_them() {
        // The packer chunks a mip at sixteen kilobytes, so a mip of more than one block is the
        // ordinary case rather than an edge: a hundred thousand textures in a full install have one.
        // A reader that decoded only the first block of each mip would still pass a one-block test.
        let mips = vec![
            vec![vec![1u8; 4096], vec![2u8; 4096], vec![3u8; 1000]],
            vec![vec![4u8; 512], vec![5u8; 256]],
        ];
        let (bytes, offset, content) = one(EntrySpec::texture_blocks(vec![0xAB; 80], mips));
        let dat = Dat::parse(&bytes).unwrap();
        let entry = dat.entry_at(offset).unwrap();
        assert_eq!(entry.block_count(), 5);
        assert_eq!(dat.read(&entry).unwrap(), content);
        assert_eq!(
            entry.stored_len(),
            Some(80 + 4096 + 4096 + 1000 + 512 + 256)
        );
    }

    #[test]
    fn a_model_section_spanning_several_blocks_walks_all_of_them() {
        let mut sections: [Vec<Vec<u8>>; 11] = Default::default();
        sections[0] = vec![b"stack".repeat(20)];
        sections[1] = vec![b"runtime".repeat(30), b"more runtime".repeat(40)];
        sections[2] = vec![vec![7u8; 4096], vec![8u8; 4096], vec![9u8; 100]];
        sections[4] = vec![vec![1u8; 300]];
        let (bytes, offset, content) = one(EntrySpec::model_blocks(sections));
        let dat = Dat::parse(&bytes).unwrap();
        let entry = dat.entry_at(offset).unwrap();
        assert_eq!(entry.block_count(), 7);
        let out = dat.read(&entry).unwrap();
        assert_eq!(out, content);
        // The written header measures each section from what its blocks decoded to, not from a
        // single block, so a run walked short would move every offset after it.
        let word = |at: usize| bytes::read_u32_le(&out, at);
        assert_eq!(word(0x28), 4096 + 4096 + 100);
        assert_eq!(word(0x10), 68 + 100 + (210 + 480));
    }

    #[test]
    fn a_texture_that_declares_more_than_it_stores_extracts_what_is_there() {
        // The volume-texture case: the declared length counts padding between mip surfaces that the
        // archive does not hold. Every other content type is held to its declared length exactly, so
        // this is the one shape where a short extraction is the right answer.
        let (bytes, offset, content) = one(EntrySpec::texture_declaring(
            vec![0xCD; 80],
            vec![vec![3u8; 512]],
            4096,
        ));
        let dat = Dat::parse(&bytes).unwrap();
        let entry = dat.entry_at(offset).unwrap();
        assert_eq!(entry.declared_len(), 4096);
        assert_eq!(entry.stored_len(), Some(80 + 512));
        assert!(entry.stored_len().is_some_and(|n| n < entry.declared_len()));
        let out = dat.read(&entry).unwrap();
        assert_eq!(out, content);
        assert_eq!(out.len() as u64, entry.stored_len().unwrap());
    }

    #[test]
    fn a_texture_header_length_is_read_from_the_first_mip_rather_than_assumed() {
        // Every texture in a real install opens with an eighty-byte header, which is exactly why the
        // length is taken from the first mip's offset instead of written down as a constant.
        let (bytes, offset, content) =
            one(EntrySpec::texture(vec![0x5Au8; 48], vec![vec![1u8; 64]]));
        let dat = Dat::parse(&bytes).unwrap();
        let entry = dat.entry_at(offset).unwrap();
        let EntryBody::Texture(table) = entry.body() else {
            panic!("expected a texture body");
        };
        assert_eq!(table.raw_header_len(), 48);
        assert_eq!(dat.read(&entry).unwrap(), content);
    }

    #[test]
    fn a_texture_declaring_a_file_but_no_mips_is_corrupt() {
        let (mut bytes, offset, _) = one(EntrySpec::texture(vec![0u8; 80], vec![vec![7u8; 64]]));
        let at = usize::try_from(offset).unwrap() + ENTRY_HEADER_LEN;
        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(0));
        assert!(matches!(
            extract(&bytes, offset),
            Err(Error::EntryCorrupt { detail, .. })
                if detail == "texture entry declares a file but no mip levels"
        ));
    }

    #[test]
    fn a_texture_header_longer_than_the_file_it_belongs_to_is_corrupt() {
        // Caught before the container-length guard, so a header claiming more than the file is a
        // statement about the entry rather than about how much of it happens to be on disk.
        let (mut bytes, offset, _) = one(EntrySpec::texture(vec![0u8; 80], vec![vec![7u8; 64]]));
        let at = usize::try_from(offset).unwrap();
        bytes[at + ENTRY_HEADER_LEN + 4..at + ENTRY_HEADER_LEN + 8]
            .copy_from_slice(&bytes::write_u32_le(0x0FFF_FF00));
        assert!(matches!(
            extract(&bytes, offset),
            Err(Error::EntryCorrupt { detail, .. })
                if detail == "texture header is longer than the file it belongs to"
        ));
    }

    #[test]
    fn a_header_over_the_cap_is_refused_before_the_container_is_read() {
        // The cap has to fire in `entry_at`, before the buffer exists: an entry declaring a gigabyte
        // of header inside a large enough archive would otherwise reserve it from four bytes. What
        // says the cap is doing the refusing, and not the read that follows it, is that a header
        // just under it comes back as the truncation it is.
        let (mut bytes, offset, _) = one(EntrySpec::standard(vec![b"payload".to_vec()]));
        let at = usize::try_from(offset).unwrap();
        let tight = DatLimits {
            max_entry_header_bytes: 4096,
            ..DatLimits::default()
        };

        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(1 << 24));
        let dat = Dat::from_source(&bytes[..], &tight).unwrap();
        assert!(matches!(dat.entry_at(offset), Err(Error::LimitExceeded)));
        assert!(matches!(
            Dat::parse(&bytes).unwrap().entry_at(offset),
            Err(Error::LimitExceeded)
        ));

        bytes[at..at + 4].copy_from_slice(&bytes::write_u32_le(4096));
        let dat = Dat::from_source(&bytes[..], &tight).unwrap();
        assert!(matches!(dat.entry_at(offset), Err(Error::Truncated { .. })));
    }

    #[test]
    fn a_spanned_container_with_no_magic_still_reads_its_entries() {
        // Nineteen of a full install's eighty-six dat files are like this. Refusing them for the
        // missing magic would make a fifth of a real install unreadable, so the header is recorded
        // as absent and the data header carries the read.
        let mut b = DatBuilder::new();
        b.no_magic()
            .entry(EntrySpec::standard(vec![b"spanned payload".to_vec()]));
        let (bytes, placed) = b.build();
        let dat = Dat::parse(&bytes).unwrap();
        assert!(dat.common_header().is_none());
        assert_eq!(dat.data_header().header_size, DATA_HEADER_LEN);
        assert_eq!(dat.data_header().declared_file_len(), bytes.len() as u64);
        assert_eq!(
            dat.read_entry_at(placed[0].offset).unwrap(),
            placed[0].content
        );
    }
}
