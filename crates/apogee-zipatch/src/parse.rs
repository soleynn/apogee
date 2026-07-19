//! The streaming ZiPatch parser. One interpreter reads the container frame by frame, verifies each
//! chunk's CRC32, and hands back the typed [`Chunk`] model; the applier and index builder (later
//! phases) ride the same execution so they cannot disagree.
//!
//! The on-disk chunk frame is `[u32be size][4-char type][payload: size bytes][u32be crc32]`, where
//! `size` counts the payload only and the CRC covers `type + payload`. Reading stops at the first
//! `EOF_` chunk (the stream is not trusted to end at EOF). Every chunk is read into one reusable
//! buffer whose length is capped before allocation, so a hostile `size` claim is a typed error, not
//! a multi-gigabyte allocation. Field endianness is enforced at each read site through
//! [`crate::bytes`].

use std::io::{self, Read};

use crate::bytes::{self, Cursor};
use crate::chunk::{
    AddData, ApplyFreeSpace, ApplyOption, Chunk, Directory, EmptyBlock, FileHeader, FileHeaderV3,
    FileOp, FileOperation, FileTarget, Header, HeaderFileKind, HeaderTargetKind, IndexCommand,
    IndexOp, MAGIC, PatchInfo, Platform, Sqpk, TargetInfo,
};
use crate::error::{Error, Limit, Op, Result};

/// The default cap on a single chunk's declared payload length: 256 MiB. Real boot and game chunks
/// top out around a megabyte; this comfortably clears them while rejecting the pathological ~4 GiB
/// `u32` claim well before allocation. Callers with a different bound set their own [`Limits`].
pub const DEFAULT_MAX_CHUNK_SIZE: u32 = 256 << 20;

/// Allocation bounds enforced while reading (all patch input is hostile).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Reject any chunk whose declared payload length exceeds this.
    pub max_chunk_size: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_chunk_size: DEFAULT_MAX_CHUNK_SIZE,
        }
    }
}

/// A streaming reader over one ZiPatch file. Construct with [`PatchReader::open`] (which validates
/// the magic), then pull chunks with [`PatchReader::next_chunk`] until it yields `None` at `EOF_`.
pub struct PatchReader<R: Read> {
    reader: R,
    /// Absolute file offset of the next chunk's `size` field.
    pos: u64,
    /// Reusable buffer holding one chunk's `type + payload + crc`.
    frame: Vec<u8>,
    limits: Limits,
    verify_crc: bool,
    done: bool,
}

impl<R: Read> PatchReader<R> {
    /// Open a patch, validating the 12-byte magic. CRC verification is on by default (boot patches
    /// carry no other integrity check); tune it with [`PatchReader::verify_crc`].
    ///
    /// # Errors
    /// [`Error::BadMagic`] if the stream does not begin with the ZiPatch magic (a short stream is
    /// treated the same: it is not a valid patch header).
    pub fn open(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; MAGIC.len()];
        if reader.read_exact(&mut magic).is_err() || magic != MAGIC {
            return Err(Error::BadMagic);
        }
        Ok(Self {
            reader,
            pos: MAGIC.len() as u64,
            frame: Vec::new(),
            limits: Limits::default(),
            verify_crc: true,
            done: false,
        })
    }

    /// Set allocation bounds.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Turn per-chunk CRC verification on or off. Off is only for the apply path once a block-SHA1
    /// list has already vouched for the bytes; the default posture is on.
    #[must_use]
    pub fn verify_crc(mut self, on: bool) -> Self {
        self.verify_crc = on;
        self
    }

    /// The absolute file offset the reader sits at: the start of the next chunk before a call to
    /// [`PatchReader::next_chunk`], the byte just past the returned chunk after one. The dump tool
    /// records it before each read to label chunks by offset.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Read and parse the next chunk, or `None` once the terminating `EOF_` chunk has been returned.
    ///
    /// The returned chunk borrows the reader's internal buffer, so it is consumed before the next
    /// call. Effects that need to outlive the borrow (paths, the `F:A` block stream) are copied or
    /// re-borrowed by the caller.
    ///
    /// # Errors
    /// A [`Error`] for any structural fault: truncation, a CRC mismatch, an over-cap chunk, an
    /// unknown chunk/command, or a malformed field. Every variant carries the offending file offset.
    pub fn next_chunk(&mut self) -> Result<Option<Chunk<'_>>> {
        if self.done {
            return Ok(None);
        }

        let chunk_start = self.pos;
        let size = self.read_size()?;
        if size > self.limits.max_chunk_size {
            return Err(Error::LimitExceeded {
                what: Limit::ChunkSize,
                value: u64::from(size),
                max: u64::from(self.limits.max_chunk_size),
            });
        }

        // `type (4) + payload (size) + crc (4)`, read in one shot into the reusable buffer.
        let size = size as usize;
        let frame_len = size + 8;
        self.fill_frame(frame_len, chunk_start + 4)?;

        let type_off = chunk_start + 4;
        let fourcc = [self.frame[0], self.frame[1], self.frame[2], self.frame[3]];

        if self.verify_crc {
            let computed = crc32fast::hash(&self.frame[..4 + size]);
            let stored = bytes::u32_be([
                self.frame[4 + size],
                self.frame[5 + size],
                self.frame[6 + size],
                self.frame[7 + size],
            ]);
            if computed != stored {
                return Err(Error::ChunkCrcMismatch {
                    offset: type_off,
                    stored,
                    computed,
                });
            }
        }

        // Stop after this chunk if it is the terminator; decide from the fourcc so the returned
        // borrow of `self.frame` does not have to outlive a later field write.
        if fourcc == *b"EOF_" {
            self.done = true;
        }
        // Advance past the whole chunk: the 4-byte size field plus `frame_len` (type + payload + crc).
        // Missing the size field here silently drifts every later chunk's absolute offset 4 bytes low.
        self.pos = chunk_start + 4 + frame_len as u64;

        let payload = &self.frame[4..4 + size];
        Ok(Some(parse_chunk(&fourcc, payload, type_off)?))
    }

    /// Read the 4-byte big-endian chunk size at the current position.
    fn read_size(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        match self.reader.read_exact(&mut buf) {
            Ok(()) => Ok(bytes::u32_be(buf)),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(Error::Truncated {
                offset: self.pos,
                needed: 4,
            }),
            Err(source) => Err(Error::Io {
                source,
                target: None,
                during: Op::Read,
            }),
        }
    }

    /// Read the next `frame_len` bytes (`type + payload + crc`) into the reusable buffer. The buffer is
    /// cleared and grown without zero-filling (every byte is about to be overwritten), and a short read
    /// is mapped to truncation at the exact byte that ran off the end, so the reported offset/needed
    /// match the `Cursor`'s field-level precision rather than the frame start.
    fn fill_frame(&mut self, frame_len: usize, frame_off: u64) -> Result<()> {
        self.frame.clear();
        self.frame.reserve(frame_len);
        match (&mut self.reader)
            .take(frame_len as u64)
            .read_to_end(&mut self.frame)
        {
            Ok(got) if got == frame_len => Ok(()),
            Ok(got) => Err(Error::Truncated {
                offset: frame_off + got as u64,
                needed: (frame_len - got) as u64,
            }),
            Err(source) => Err(Error::Io {
                source,
                target: None,
                during: Op::Read,
            }),
        }
    }
}

/// Dispatch a chunk by its fourcc. `payload` is the chunk body (after the type); `type_off` is the
/// absolute file offset of the fourcc, so `payload` begins at `type_off + 4`.
fn parse_chunk<'a>(fourcc: &[u8; 4], payload: &'a [u8], type_off: u64) -> Result<Chunk<'a>> {
    let payload_off = type_off + 4;
    match fourcc {
        b"FHDR" => Ok(Chunk::FileHeader(parse_file_header(payload, payload_off)?)),
        b"APLY" => Ok(Chunk::ApplyOption(parse_apply_option(
            payload,
            payload_off,
        )?)),
        b"APFS" => Ok(Chunk::ApplyFreeSpace(parse_apply_free_space(
            payload,
            payload_off,
        )?)),
        b"ADIR" => Ok(Chunk::AddDirectory(parse_directory(payload, payload_off)?)),
        b"DELD" => Ok(Chunk::DeleteDirectory(parse_directory(
            payload,
            payload_off,
        )?)),
        b"SQPK" => Ok(Chunk::Sqpk(parse_sqpk(payload, payload_off)?)),
        b"EOF_" => Ok(Chunk::EndOfFile),
        b"XXXX" => Ok(Chunk::Padding),
        _ => Err(Error::UnknownChunk {
            fourcc: *fourcc,
            offset: type_off,
        }),
    }
}

fn parse_file_header(payload: &[u8], base: u64) -> Result<FileHeader> {
    let mut c = Cursor::new(payload, base);
    // The version dword is read little-endian (an XL/format quirk); the version is bits 16..24.
    let version = (c.u32_le()? >> 16) as u8;
    let pt = c.take(4)?;
    let patch_type = [pt[0], pt[1], pt[2], pt[3]];
    let entry_files = c.u32_be()?;
    let v3 = if version == 3 {
        let add_directories = c.u32_be()?;
        let delete_directories = c.u32_be()?;
        // deleteDataSize is a little-endian pair of big-endian dwords: low then high.
        let lo = c.u32_be()?;
        let hi = c.u32_be()?;
        let delete_data_size = u64::from(lo) | (u64::from(hi) << 32);
        Some(FileHeaderV3 {
            add_directories,
            delete_directories,
            delete_data_size,
            minor_version: c.u32_be()?,
            repository_name: c.u32_be()?,
            commands: c.u32_be()?,
            sqpk_add: c.u32_be()?,
            sqpk_delete: c.u32_be()?,
            sqpk_expand: c.u32_be()?,
            sqpk_header: c.u32_be()?,
            sqpk_file: c.u32_be()?,
        })
    } else {
        None
    };
    Ok(FileHeader {
        version,
        patch_type,
        entry_files,
        v3,
    })
}

fn parse_apply_option(payload: &[u8], base: u64) -> Result<ApplyOption> {
    let mut c = Cursor::new(payload, base);
    let kind = c.u32_be()?;
    c.skip(4)?; // discarded padding, observed 0x0000_0004
    let value = c.u32_be()? != 0;
    Ok(ApplyOption::new(kind, value))
}

fn parse_apply_free_space(payload: &[u8], base: u64) -> Result<ApplyFreeSpace> {
    let mut c = Cursor::new(payload, base);
    Ok(ApplyFreeSpace {
        field_a: c.i64_be()?,
        field_b: c.i64_be()?,
    })
}

fn parse_directory(payload: &[u8], base: u64) -> Result<Directory> {
    let mut c = Cursor::new(payload, base);
    let len = c.u32_be()? as usize;
    let raw = c.take(len)?;
    Ok(Directory {
        path: decode_path(raw),
    })
}

fn parse_sqpk(payload: &[u8], base: u64) -> Result<Sqpk<'_>> {
    let mut c = Cursor::new(payload, base);
    let inner_size = c.u32_be()?;
    if u64::from(inner_size) != payload.len() as u64 {
        return Err(Error::Corrupt {
            offset: base,
            detail: "sqpk inner size disagrees with chunk size",
        });
    }
    let cmd_off = c.offset();
    let command = c.u8()?;
    match command {
        b'T' => Ok(Sqpk::TargetInfo(parse_target_info(&mut c)?)),
        b'X' => Ok(Sqpk::PatchInfo(parse_patch_info(&mut c)?)),
        b'A' => Ok(Sqpk::AddData(parse_add_data(&mut c)?)),
        b'D' => Ok(Sqpk::DeleteData(parse_empty_block(&mut c)?)),
        b'E' => Ok(Sqpk::ExpandData(parse_empty_block(&mut c)?)),
        b'H' => Ok(Sqpk::Header(parse_header(&mut c)?)),
        b'F' => Ok(Sqpk::File(parse_file_op(&mut c)?)),
        b'I' => Ok(Sqpk::Index(parse_index(&mut c)?)),
        cmd => Err(Error::UnknownCommand {
            cmd,
            offset: cmd_off,
        }),
    }
}

/// The `mainId`/`subId`/`fileId` file-target triple shared by A/D/E/H/I.
fn parse_target(c: &mut Cursor<'_>) -> Result<FileTarget> {
    Ok(FileTarget {
        main_id: c.u16_be()?,
        sub_id: c.u16_be()?,
        file_id: c.u32_be()?,
    })
}

fn parse_target_info(c: &mut Cursor<'_>) -> Result<TargetInfo> {
    c.skip(3)?; // reserved / alignment
    let platform_off = c.offset();
    let platform = Platform::from_u16(c.u16_be()?).ok_or(Error::Corrupt {
        offset: platform_off,
        detail: "unknown target platform",
    })?;
    let region = c.i16_be()?;
    let is_debug = c.i16_be()? != 0;
    let version = c.u16_be()?;
    // These two sizes are little-endian (game-native), unlike the big-endian words above them.
    let deleted_data_size = c.u64_le()?;
    let seek_count = c.u64_le()?;
    Ok(TargetInfo {
        platform,
        region,
        is_debug,
        version,
        deleted_data_size,
        seek_count,
    })
}

fn parse_patch_info(c: &mut Cursor<'_>) -> Result<PatchInfo> {
    let status = c.u8()?;
    let version = c.u8()?;
    c.skip(1)?; // alignment
    let install_size = c.u64_be()?;
    Ok(PatchInfo {
        status,
        version,
        install_size,
    })
}

fn parse_add_data<'a>(c: &mut Cursor<'a>) -> Result<AddData<'a>> {
    c.skip(3)?; // alignment
    let target = parse_target(c)?;
    // Every dat offset/length is stored `>> 7` (128-byte aligned). Expanding into `u64` cannot
    // overflow: a `u32 << 7` is at most 2^39.
    let block_offset = u64::from(c.u32_be()?) << 7;
    let block_size = u64::from(c.u32_be()?) << 7;
    let block_delete_size = u64::from(c.u32_be()?) << 7;
    let data_off = c.offset();
    let data = c.take(usize::try_from(block_size).map_err(|_| Error::Corrupt {
        offset: c.offset(),
        detail: "add-data block size exceeds usize",
    })?)?;
    Ok(AddData {
        target,
        block_offset,
        block_size,
        block_delete_size,
        data,
        data_off,
    })
}

fn parse_empty_block(c: &mut Cursor<'_>) -> Result<EmptyBlock> {
    c.skip(3)?; // alignment
    let target = parse_target(c)?;
    let block_offset = u64::from(c.u32_be()?) << 7;
    let block_count = c.u32_be()?; // block count, not shifted
    c.skip(4)?; // reserved
    Ok(EmptyBlock {
        target,
        block_offset,
        block_count,
    })
}

fn parse_header<'a>(c: &mut Cursor<'a>) -> Result<Header<'a>> {
    let file_kind = HeaderFileKind::parse(c.u8()?);
    let header_kind = HeaderTargetKind::parse(c.u8()?);
    c.skip(1)?; // alignment
    let target = parse_target(c)?;
    let data_off = c.offset();
    let data = c.take(Header::HEADER_LEN)?;
    Ok(Header {
        file_kind,
        header_kind,
        target,
        data,
        data_off,
    })
}

fn parse_file_op<'a>(c: &mut Cursor<'a>) -> Result<FileOp<'a>> {
    let operation = FileOperation::parse(c.u8()?);
    c.skip(2)?; // alignment
    let file_offset = c.i64_be()?;
    let file_size = c.i64_be()?;
    let path_len = c.u32_be()? as usize;
    let expansion_id = c.u16_be()?;
    c.skip(2)?; // padding
    let path = decode_path(c.take(path_len)?);
    // Only AddFile is followed by the compressed-block stream; the rest carry no trailing data.
    let blocks_off = c.offset();
    let blocks: &'a [u8] = if operation == FileOperation::AddFile {
        c.rest()
    } else {
        &[]
    };
    Ok(FileOp {
        operation,
        file_offset,
        file_size,
        expansion_id,
        path,
        blocks,
        blocks_off,
    })
}

fn parse_index(c: &mut Cursor<'_>) -> Result<IndexCommand> {
    let command = IndexOp::parse(c.u8()?);
    let is_synonym = c.u8()? != 0;
    c.skip(1)?; // alignment
    let target = parse_target(c)?;
    let file_hash = c.u64_be()?;
    let block_offset = c.u32_be()?;
    let block_number = c.u32_be()?;
    Ok(IndexCommand {
        command,
        is_synonym,
        target,
        file_hash,
        block_offset,
        block_number,
    })
}

/// Decode a fixed-length path field the way the reference's `ReadFixedLengthString` does:
/// `Encoding.ASCII.GetString` (one char per byte, every byte >= 0x80 mapped to `?`) with trailing
/// NULs trimmed. Matching the oracle byte-for-byte keeps path resolution identical even on the
/// non-ASCII bytes a hostile patch might inject; the result is confined against the game root anyway.
fn decode_path(raw: &[u8]) -> String {
    let mut s: String = raw
        .iter()
        .map(|&b| if b < 0x80 { b as char } else { '?' })
        .collect();
    s.truncate(s.trim_end_matches('\0').len());
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::{ApplyOptionKind, IndexOp};
    use proptest::prelude::*;

    /// Builds ZiPatch bytes chunk by chunk, framing each `[size][type][payload][crc]` exactly as the
    /// container does (size and crc big-endian; crc over type+payload). SQPK chunks get the
    /// `innerSize`/command prefix. The output feeds a real [`PatchReader`].
    #[derive(Default)]
    struct PatchBuilder {
        body: Vec<u8>,
    }

    impl PatchBuilder {
        fn new() -> Self {
            Self::default()
        }

        fn chunk(&mut self, fourcc: &[u8; 4], payload: &[u8]) -> &mut Self {
            self.frame(fourcc, payload, true)
        }

        /// Like [`Self::chunk`] but stamps a deliberately wrong CRC.
        fn chunk_bad_crc(&mut self, fourcc: &[u8; 4], payload: &[u8]) -> &mut Self {
            self.frame(fourcc, payload, false)
        }

        fn frame(&mut self, fourcc: &[u8; 4], payload: &[u8], good_crc: bool) -> &mut Self {
            self.body
                .extend_from_slice(&bytes::write_u32_be(payload.len() as u32));
            self.body.extend_from_slice(fourcc);
            self.body.extend_from_slice(payload);
            let mut crc_input = fourcc.to_vec();
            crc_input.extend_from_slice(payload);
            let crc = crc32fast::hash(&crc_input);
            let crc = if good_crc { crc } else { crc ^ 0xFFFF_FFFF };
            self.body.extend_from_slice(&bytes::write_u32_be(crc));
            self
        }

        /// Frame a SQPK chunk: `innerSize` (== payload len) + 1-char command + command payload.
        fn sqpk(&mut self, command: u8, cmd_payload: &[u8]) -> &mut Self {
            let inner_len = (4 + 1 + cmd_payload.len()) as u32;
            let mut payload = Vec::new();
            payload.extend_from_slice(&bytes::write_u32_be(inner_len));
            payload.push(command);
            payload.extend_from_slice(cmd_payload);
            self.chunk(b"SQPK", &payload)
        }

        fn eof(&mut self) -> &mut Self {
            self.chunk(b"EOF_", &[])
        }

        /// The full file: magic, chunks, no implicit `EOF_` (callers add one).
        fn bytes(&self) -> Vec<u8> {
            let mut out = MAGIC.to_vec();
            out.extend_from_slice(&self.body);
            out
        }
    }

    /// The 8-byte file-target triple: mainId/subId big-endian u16, fileId big-endian u32.
    fn target(main_id: u16, sub_id: u16, file_id: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&bytes::write_u16_be(main_id));
        v.extend_from_slice(&bytes::write_u16_be(sub_id));
        v.extend_from_slice(&bytes::write_u32_be(file_id));
        v
    }

    /// Parse a whole patch into owned effect strings (the dump the tool prints), so assertions read
    /// against the Display rendering as well as the typed model.
    fn parse_all(patch: &[u8]) -> Result<Vec<String>> {
        let mut reader = PatchReader::open(patch)?;
        let mut lines = Vec::new();
        while let Some(chunk) = reader.next_chunk()? {
            lines.push(chunk.to_string());
        }
        Ok(lines)
    }

    #[test]
    fn open_validates_the_magic() {
        assert!(matches!(
            PatchReader::open(b"not a patch!!".as_slice()),
            Err(Error::BadMagic)
        ));
        // A stream shorter than the magic is not a valid header either.
        assert!(matches!(
            PatchReader::open([0x91, 0x5A].as_slice()),
            Err(Error::BadMagic)
        ));
        // The exact magic opens.
        assert!(PatchReader::open(MAGIC.as_slice()).is_ok());
    }

    #[test]
    fn parses_a_boot_shaped_patch_end_to_end() {
        // FHDR v2 / APLY / SQPK T / SQPK F:A / EOF_ — the shape a real boot patch takes.
        let mut fhdr = Vec::new();
        fhdr.extend_from_slice(&bytes::write_u32_le(0x0002_0000)); // version dword (LE): v2
        fhdr.extend_from_slice(b"DIFF");
        fhdr.extend_from_slice(&bytes::write_u32_be(5)); // entryFiles
        fhdr.extend_from_slice(&[0u8; 8]); // v2 trailing zeros

        let mut aply = Vec::new();
        aply.extend_from_slice(&bytes::write_u32_be(1)); // IgnoreMissing
        aply.extend_from_slice(&bytes::write_u32_be(4)); // pad
        aply.extend_from_slice(&bytes::write_u32_be(0)); // value = false

        let mut t = Vec::new();
        t.extend_from_slice(&[0, 0, 0]); // reserved
        t.extend_from_slice(&bytes::write_u16_be(0)); // platform Win32
        t.extend_from_slice(&bytes::write_u16_be(0xFFFF)); // region -1
        t.extend_from_slice(&bytes::write_u16_be(0)); // isDebug
        t.extend_from_slice(&bytes::write_u16_be(0)); // version
        t.extend_from_slice(&bytes::write_u64_le(0)); // deletedDataSize (LE)
        t.extend_from_slice(&bytes::write_u64_le(0)); // seekCount (LE)

        let mut f = Vec::new();
        f.push(b'A'); // AddFile
        f.extend_from_slice(&[0, 0]); // alignment
        f.extend_from_slice(&bytes::write_i64_be(0)); // fileOffset
        f.extend_from_slice(&bytes::write_i64_be(4)); // fileSize
        f.extend_from_slice(&bytes::write_u32_be(14)); // pathLen
        f.extend_from_slice(&bytes::write_u16_be(0)); // expansionId
        f.extend_from_slice(&[0, 0]); // pad
        f.extend_from_slice(b"ffxivboot.exe\0"); // path (14 bytes, one trailing NUL)
        f.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x12]); // compressed-block bytes (opaque here)

        let mut b = PatchBuilder::new();
        b.chunk(b"FHDR", &fhdr)
            .chunk(b"APLY", &aply)
            .sqpk(b'T', &t)
            .sqpk(b'F', &f)
            .eof();
        let patch = b.bytes();

        let mut reader = PatchReader::open(&patch[..]).unwrap();
        let mut chunks = Vec::new();
        while let Some(c) = reader.next_chunk().unwrap() {
            chunks.push(format!("{c:?}"));
        }
        // Five chunks, in order, terminating at EOF_.
        assert_eq!(chunks.len(), 5);

        // Re-parse for typed assertions.
        let mut reader = PatchReader::open(&patch[..]).unwrap();
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::FileHeader(h) => {
                assert_eq!(h.version, 2);
                assert_eq!(h.patch_type_str(), "DIFF");
                assert_eq!(h.entry_files, 5);
                assert!(h.v3.is_none());
            }
            other => panic!("expected FHDR, got {other:?}"),
        }
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::ApplyOption(a) => {
                assert_eq!(a.kind, ApplyOptionKind::IgnoreMissing);
                assert!(!a.value);
            }
            other => panic!("expected APLY, got {other:?}"),
        }
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::TargetInfo(t)) => {
                assert_eq!(t.platform, Platform::Win32);
                assert_eq!(t.region, -1);
            }
            other => panic!("expected SQPK T, got {other:?}"),
        }
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::File(file)) => {
                assert_eq!(file.operation, FileOperation::AddFile);
                assert_eq!(file.path, "ffxivboot.exe");
                assert_eq!(file.file_size, 4);
                assert_eq!(file.blocks, &[0xAB, 0xCD, 0xEF, 0x12]);
            }
            other => panic!("expected SQPK F, got {other:?}"),
        }
        assert!(matches!(
            reader.next_chunk().unwrap(),
            Some(Chunk::EndOfFile)
        ));
        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn fhdr_version_is_a_little_endian_dword() {
        // The version lives in bits 16..24 of a *little-endian* dword; every other FHDR field is
        // big-endian. Bytes 00 00 03 00 -> 0x0003_0000 -> version 3.
        let mut fhdr = Vec::new();
        fhdr.extend_from_slice(&[0x00, 0x00, 0x03, 0x00]); // LE dword => v3
        fhdr.extend_from_slice(b"HIST");
        fhdr.extend_from_slice(&bytes::write_u32_be(7)); // entryFiles (BE)
        // v3 tail: 12 big-endian dwords, then trailing unknown bytes we can omit.
        fhdr.extend_from_slice(&bytes::write_u32_be(1)); // addDirectories
        fhdr.extend_from_slice(&bytes::write_u32_be(2)); // deleteDirectories
        fhdr.extend_from_slice(&bytes::write_u32_be(0x1111_2222)); // deleteDataSize lo
        fhdr.extend_from_slice(&bytes::write_u32_be(0x0000_0001)); // deleteDataSize hi
        fhdr.extend_from_slice(&bytes::write_u32_be(9)); // minorVersion
        fhdr.extend_from_slice(&bytes::write_u32_be(0)); // repositoryName
        fhdr.extend_from_slice(&bytes::write_u32_be(50)); // commands
        fhdr.extend_from_slice(&bytes::write_u32_be(45)); // sqpkAdd
        fhdr.extend_from_slice(&bytes::write_u32_be(3)); // sqpkDelete
        fhdr.extend_from_slice(&bytes::write_u32_be(0)); // sqpkExpand
        fhdr.extend_from_slice(&bytes::write_u32_be(1)); // sqpkHeader
        fhdr.extend_from_slice(&bytes::write_u32_be(48)); // sqpkFile
        fhdr.extend_from_slice(&[0u8; 0xB8]); // trailing unknown, ignored

        let mut b = PatchBuilder::new();
        b.chunk(b"FHDR", &fhdr).eof();
        let patch = b.bytes();

        let mut reader = PatchReader::open(&patch[..]).unwrap();
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::FileHeader(h) => {
                assert_eq!(h.version, 3);
                assert_eq!(h.patch_type_str(), "HIST");
                assert_eq!(h.entry_files, 7);
                let v3 = h.v3.expect("v3 tail");
                assert_eq!(v3.add_directories, 1);
                assert_eq!(v3.delete_directories, 2);
                // low dword | (high dword << 32)
                assert_eq!(v3.delete_data_size, 0x0000_0001_1111_2222);
                assert_eq!(v3.sqpk_file, 48);
            }
            other => panic!("expected FHDR, got {other:?}"),
        }
    }

    #[test]
    fn target_info_mixes_big_and_little_endian() {
        // The endianness foot-gun in one command: platform/region/version are big-endian u16, but
        // deletedDataSize/seekCount are little-endian u64. Pin the exact bytes.
        let mut t = Vec::new();
        t.extend_from_slice(&[0, 0, 0]); // reserved
        t.extend_from_slice(&[0x00, 0x00]); // platform 0 (Win32), BE
        t.extend_from_slice(&[0xFF, 0xFF]); // region -1, BE i16
        t.extend_from_slice(&[0x00, 0x01]); // isDebug = 1 (BE i16, non-zero)
        t.extend_from_slice(&[0x12, 0x34]); // version 0x1234, BE
        t.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // deletedDataSize LE
        t.extend_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00]); // seekCount LE

        let mut b = PatchBuilder::new();
        b.sqpk(b'T', &t).eof();
        let patch = b.bytes();

        let mut reader = PatchReader::open(&patch[..]).unwrap();
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::TargetInfo(t)) => {
                assert_eq!(t.platform, Platform::Win32);
                assert_eq!(t.region, -1);
                assert!(t.is_debug);
                assert_eq!(t.version, 0x1234);
                // LE: least-significant byte first.
                assert_eq!(t.deleted_data_size, 0x0807_0605_0403_0201);
                assert_eq!(t.seek_count, 0x0000_0000_dead_beef);
            }
            other => panic!("expected SQPK T, got {other:?}"),
        }
    }

    #[test]
    fn add_data_offsets_are_big_endian_shifted_left_seven() {
        // A/D/E offsets and counts are big-endian u32 stored `>> 7`. Reading must shift back.
        let mut a = Vec::new();
        a.extend_from_slice(&[0, 0, 0]); // alignment
        a.extend_from_slice(&target(0x0a, 0x0000, 0)); // dat 0a0000.win32.dat0
        a.extend_from_slice(&bytes::write_u32_be(3)); // blockOffset (<<7 => 384)
        a.extend_from_slice(&bytes::write_u32_be(1)); // blockNumber (<<7 => 128 bytes of data)
        a.extend_from_slice(&bytes::write_u32_be(2)); // blockDeleteNumber (<<7 => 256)
        a.extend_from_slice(&[0x55u8; 128]); // exactly blockNumber<<7 data bytes

        let mut b = PatchBuilder::new();
        b.sqpk(b'A', &a).eof();
        let patch = b.bytes();

        let mut reader = PatchReader::open(&patch[..]).unwrap();
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::AddData(add)) => {
                assert_eq!(
                    add.target.dat_path(Platform::Win32),
                    "sqpack/ffxiv/0a0000.win32.dat0"
                );
                assert_eq!(add.block_offset, 384);
                assert_eq!(add.block_size, 128);
                assert_eq!(add.block_delete_size, 256);
                assert_eq!(add.data.len(), 128);
                assert!(add.data.iter().all(|&x| x == 0x55));
            }
            other => panic!("expected SQPK A, got {other:?}"),
        }
    }

    #[test]
    fn delete_and_expand_share_a_layout_but_distinct_variants() {
        // D and E have identical payload; block_count is *not* shifted.
        let mut de = Vec::new();
        de.extend_from_slice(&[0, 0, 0]);
        de.extend_from_slice(&target(0x0a, 0x0000, 1));
        de.extend_from_slice(&bytes::write_u32_be(4)); // blockOffset <<7 => 512
        de.extend_from_slice(&bytes::write_u32_be(6)); // blockCount, NOT shifted
        de.extend_from_slice(&bytes::write_u32_be(0)); // reserved

        let mut b = PatchBuilder::new();
        b.sqpk(b'D', &de).sqpk(b'E', &de).eof();
        let patch = b.bytes();

        let mut reader = PatchReader::open(&patch[..]).unwrap();
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::DeleteData(d)) => {
                assert_eq!(d.block_offset, 512);
                assert_eq!(d.block_count, 6);
                assert_eq!(d.byte_len(), 6 * 128);
            }
            other => panic!("expected SQPK D, got {other:?}"),
        }
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::ExpandData(e)) => {
                assert_eq!(e.block_offset, 512);
                assert_eq!(e.block_count, 6);
            }
            other => panic!("expected SQPK E, got {other:?}"),
        }
    }

    #[test]
    fn header_command_carries_a_1024_byte_blob() {
        let mut h = Vec::new();
        h.push(b'I'); // fileKind = Index
        h.push(b'V'); // headerKind = Version
        h.push(0); // alignment
        h.extend_from_slice(&target(0x0a, 0x0000, 0));
        h.extend_from_slice(&[0x77u8; Header::HEADER_LEN]);

        let mut b = PatchBuilder::new();
        b.sqpk(b'H', &h).eof();
        let patch = b.bytes();

        let mut reader = PatchReader::open(&patch[..]).unwrap();
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::Header(header)) => {
                assert_eq!(header.file_kind, HeaderFileKind::Index);
                assert_eq!(header.header_kind, HeaderTargetKind::Version);
                assert!(header.file_kind.is_index());
                assert_eq!(header.header_kind.write_offset(), 0);
                assert_eq!(header.data.len(), Header::HEADER_LEN);
                assert!(header.data.iter().all(|&x| x == 0x77));
                assert_eq!(
                    header.target.index_path(Platform::Win32),
                    "sqpack/ffxiv/0a0000.win32.index"
                );
            }
            other => panic!("expected SQPK H, got {other:?}"),
        }
    }

    #[test]
    fn file_op_remove_all_and_delete_carry_no_blocks() {
        // Only F:A is followed by a compressed-block stream; F:R and F:D are not.
        let build_f = |op: u8, path: &str, trailing: &[u8]| {
            let mut f = Vec::new();
            f.push(op);
            f.extend_from_slice(&[0, 0]);
            f.extend_from_slice(&bytes::write_i64_be(0));
            f.extend_from_slice(&bytes::write_i64_be(0));
            f.extend_from_slice(&bytes::write_u32_be(path.len() as u32));
            f.extend_from_slice(&bytes::write_u16_be(1)); // expansionId
            f.extend_from_slice(&[0, 0]);
            f.extend_from_slice(path.as_bytes());
            f.extend_from_slice(trailing);
            f
        };

        let mut b = PatchBuilder::new();
        b.sqpk(b'F', &build_f(b'R', "sqpack/ex1", &[]))
            .sqpk(b'F', &build_f(b'D', "sqpack/ex1/0a0000.win32.dat0", &[]))
            .eof();
        let patch = b.bytes();

        let mut reader = PatchReader::open(&patch[..]).unwrap();
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::File(f)) => {
                assert_eq!(f.operation, FileOperation::RemoveAll);
                assert_eq!(f.expansion_id, 1);
                assert!(f.blocks.is_empty());
            }
            other => panic!("expected SQPK F:R, got {other:?}"),
        }
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::File(f)) => {
                assert_eq!(f.operation, FileOperation::DeleteFile);
                assert!(f.blocks.is_empty());
            }
            other => panic!("expected SQPK F:D, got {other:?}"),
        }
    }

    #[test]
    fn index_command_and_directory_and_padding_and_free_space_parse() {
        let mut i = Vec::new();
        i.push(b'A'); // Add
        i.push(1); // isSynonym
        i.push(0); // alignment
        i.extend_from_slice(&target(0x0a, 0x0000, 0));
        i.extend_from_slice(&bytes::write_u64_be(0xDEAD_BEEF_CAFE_F00D));
        i.extend_from_slice(&bytes::write_u32_be(10));
        i.extend_from_slice(&bytes::write_u32_be(20));

        let mut adir = Vec::new();
        adir.extend_from_slice(&bytes::write_u32_be(6));
        adir.extend_from_slice(b"/movie");

        let mut apfs = Vec::new();
        apfs.extend_from_slice(&bytes::write_i64_be(-5));
        apfs.extend_from_slice(&bytes::write_i64_be(9));

        let mut b = PatchBuilder::new();
        b.sqpk(b'I', &i)
            .chunk(b"ADIR", &adir)
            .chunk(b"DELD", &adir)
            .chunk(b"APFS", &apfs)
            .chunk(b"XXXX", &[0xAA, 0xBB])
            .eof();
        let patch = b.bytes();

        let chunks: Vec<_> = {
            let mut reader = PatchReader::open(&patch[..]).unwrap();
            let mut v = Vec::new();
            while let Some(c) = reader.next_chunk().unwrap() {
                v.push(format!("{c}"));
            }
            v
        };
        assert_eq!(
            chunks[0],
            "SQPK I add sqpack/ffxiv/0a0000.win32.index synonym=true hash=0xdeadbeefcafef00d"
        );
        assert_eq!(chunks[1], "ADIR /movie");
        assert_eq!(chunks[2], "DELD /movie");
        assert_eq!(chunks[3], "APFS -5 9");
        assert_eq!(chunks[4], "XXXX");
        assert_eq!(chunks[5], "EOF_");

        // Re-parse the index command for its typed fields.
        let mut reader = PatchReader::open(&patch[..]).unwrap();
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::Index(idx)) => {
                assert_eq!(idx.command, IndexOp::Add);
                assert!(idx.is_synonym);
                assert_eq!(idx.file_hash, 0xDEAD_BEEF_CAFE_F00D);
                assert_eq!(idx.block_offset, 10);
                assert_eq!(idx.block_number, 20);
            }
            other => panic!("expected SQPK I, got {other:?}"),
        }
    }

    #[test]
    fn chunk_size_field_is_big_endian() {
        // A one-byte XXXX payload makes the first size field 00 00 00 01 — a value whose byte order
        // matters. Read big-endian it is 1 and the chunk frames cleanly; read little-endian it would
        // be 0x0100_0000 (16 MiB), so the reader would try to frame a 16 MiB chunk and desync into a
        // truncation. A clean parse here therefore pins the size field as big-endian.
        let patch = {
            let mut b = PatchBuilder::new();
            b.chunk(b"XXXX", &[0x99]).eof();
            b.bytes()
        };
        assert_eq!(&patch[12..16], &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            parse_all(&patch).unwrap(),
            vec!["XXXX".to_string(), "EOF_".to_string()]
        );
    }

    #[test]
    fn patch_info_install_size_is_big_endian() {
        // X carries status:u8, version:u8, one alignment byte, then a big-endian u64 install size.
        // Real boot patches contain an X; pin its fields and the install_size byte order.
        let mut x = Vec::new();
        x.push(3); // status
        x.push(1); // version
        x.push(0); // alignment
        x.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A]); // install_size BE = 42

        let mut b = PatchBuilder::new();
        b.sqpk(b'X', &x).eof();
        let patch = b.bytes();

        let mut reader = PatchReader::open(&patch[..]).unwrap();
        match reader.next_chunk().unwrap().unwrap() {
            Chunk::Sqpk(Sqpk::PatchInfo(info)) => {
                assert_eq!(info.status, 3);
                assert_eq!(info.version, 1);
                // Big-endian: a little-endian read would see 0x2A00_0000_0000_0000.
                assert_eq!(info.install_size, 42);
            }
            other => panic!("expected SQPK X, got {other:?}"),
        }
    }

    #[test]
    fn dump_lines_render_the_boot_shape() {
        let mut fhdr = Vec::new();
        fhdr.extend_from_slice(&bytes::write_u32_le(0x0002_0000));
        fhdr.extend_from_slice(b"DIFF");
        fhdr.extend_from_slice(&bytes::write_u32_be(2));
        fhdr.extend_from_slice(&[0u8; 8]);

        let mut b = PatchBuilder::new();
        b.chunk(b"FHDR", &fhdr).eof();
        assert_eq!(
            parse_all(&b.bytes()).unwrap(),
            vec![
                "FHDR v2 type=DIFF entry_files=2".to_string(),
                "EOF_".to_string(),
            ]
        );
    }

    // --- hostile input: every fault is a typed error at an offset, never a panic ---

    #[test]
    fn a_wrong_chunk_crc_is_rejected() {
        let mut b = PatchBuilder::new();
        b.chunk_bad_crc(b"XXXX", &[0x01, 0x02]).eof();
        let patch = b.bytes();
        match PatchReader::open(&patch[..]).unwrap().next_chunk() {
            Err(Error::ChunkCrcMismatch { offset, .. }) => assert_eq!(offset, 16),
            other => panic!("expected CRC mismatch, got {other:?}"),
        }
    }

    #[test]
    fn crc_verification_can_be_disabled_for_the_hashed_apply_path() {
        let mut b = PatchBuilder::new();
        b.chunk_bad_crc(b"XXXX", &[0x01, 0x02]).eof();
        let patch = b.bytes();
        let mut reader = PatchReader::open(&patch[..]).unwrap().verify_crc(false);
        assert!(matches!(reader.next_chunk().unwrap(), Some(Chunk::Padding)));
        assert!(matches!(
            reader.next_chunk().unwrap(),
            Some(Chunk::EndOfFile)
        ));
    }

    #[test]
    fn an_oversize_chunk_is_a_limit_error_before_allocation() {
        // Declare a 4 KiB chunk but cap at 16 bytes: rejected on the size field, no giant alloc.
        let mut b = PatchBuilder::new();
        b.chunk(b"XXXX", &vec![0u8; 4096]).eof();
        let patch = b.bytes();
        let limits = Limits { max_chunk_size: 16 };
        let mut reader = PatchReader::open(&patch[..]).unwrap().with_limits(limits);
        match reader.next_chunk() {
            Err(Error::LimitExceeded {
                what: Limit::ChunkSize,
                value,
                max,
            }) => {
                assert_eq!(value, 4096);
                assert_eq!(max, 16);
            }
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_chunk_body_is_truncated() {
        let mut b = PatchBuilder::new();
        b.chunk(b"XXXX", &[0u8; 32]);
        let mut patch = b.bytes();
        patch.truncate(patch.len() - 10); // cut into the payload
        match PatchReader::open(&patch[..]).unwrap().next_chunk() {
            Err(Error::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_chunk_type_is_reported_with_its_offset() {
        let mut b = PatchBuilder::new();
        b.chunk(b"ZZZZ", &[]).eof();
        let patch = b.bytes();
        match PatchReader::open(&patch[..]).unwrap().next_chunk() {
            Err(Error::UnknownChunk { fourcc, offset }) => {
                assert_eq!(&fourcc, b"ZZZZ");
                assert_eq!(offset, 16); // fourcc sits right after the 12-byte magic + 4-byte size
            }
            other => panic!("expected UnknownChunk, got {other:?}"),
        }
    }

    #[test]
    fn later_chunk_offsets_stay_file_absolute() {
        // A padding chunk with a 4-byte payload, then an unknown chunk. The unknown chunk's reported
        // offset must account for the full first chunk on disk (size 4 + type 4 + payload 4 + crc 4 =
        // 16), so it sits at magic(12) + 16 + size(4) = 32. A parser that forgets the size field when
        // advancing would report 28.
        let mut b = PatchBuilder::new();
        b.chunk(b"XXXX", &[1, 2, 3, 4]).chunk(b"ZZZZ", &[]);
        let patch = b.bytes();
        let mut reader = PatchReader::open(&patch[..]).unwrap();
        assert!(matches!(reader.next_chunk().unwrap(), Some(Chunk::Padding)));
        // After the first chunk, `position` is the second chunk's size field: 12 + 16 = 28.
        assert_eq!(reader.position(), 28);
        match reader.next_chunk() {
            Err(Error::UnknownChunk { offset, .. }) => assert_eq!(offset, 32),
            other => panic!("expected UnknownChunk at 32, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_sqpk_command_is_reported_with_its_offset() {
        let mut b = PatchBuilder::new();
        b.sqpk(b'Z', &[0, 0, 0]).eof();
        let patch = b.bytes();
        match PatchReader::open(&patch[..]).unwrap().next_chunk() {
            Err(Error::UnknownCommand { cmd, offset }) => {
                assert_eq!(cmd, b'Z');
                // magic(12) + size(4) + type(4) + innerSize(4) = command byte at offset 24.
                assert_eq!(offset, 24);
            }
            other => panic!("expected UnknownCommand, got {other:?}"),
        }
    }

    #[test]
    fn a_sqpk_inner_size_disagreement_is_corrupt() {
        // Hand-build a SQPK chunk whose innerSize field lies about the payload length.
        let mut payload = Vec::new();
        payload.extend_from_slice(&bytes::write_u32_be(999)); // innerSize != real length
        payload.push(b'X');
        payload.extend_from_slice(&[0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]); // an X body
        let mut b = PatchBuilder::new();
        b.chunk(b"SQPK", &payload).eof();
        let patch = b.bytes();
        match PatchReader::open(&patch[..]).unwrap().next_chunk() {
            Err(Error::Corrupt { detail, .. }) => {
                assert_eq!(detail, "sqpk inner size disagrees with chunk size");
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_target_platform_is_corrupt() {
        let mut t = Vec::new();
        t.extend_from_slice(&[0, 0, 0]);
        t.extend_from_slice(&bytes::write_u16_be(9)); // not 0/1/2
        t.extend_from_slice(&[0u8; 2 + 2 + 2 + 8 + 8]);
        let mut b = PatchBuilder::new();
        b.sqpk(b'T', &t).eof();
        let patch = b.bytes();
        match PatchReader::open(&patch[..]).unwrap().next_chunk() {
            Err(Error::Corrupt { detail, .. }) => assert_eq!(detail, "unknown target platform"),
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn a_patch_without_eof_truncates_rather_than_looping() {
        // No EOF_ chunk: after the last real chunk, reading the next size hits end-of-stream.
        let mut b = PatchBuilder::new();
        b.chunk(b"XXXX", &[]);
        let patch = b.bytes();
        let mut reader = PatchReader::open(&patch[..]).unwrap();
        assert!(matches!(reader.next_chunk().unwrap(), Some(Chunk::Padding)));
        match reader.next_chunk() {
            Err(Error::Truncated { .. }) => {}
            other => panic!("expected Truncated at end-of-stream, got {other:?}"),
        }
    }

    #[test]
    fn parsing_stops_at_eof_ignoring_trailing_bytes() {
        // The stream is not trusted to end at EOF_: bytes after it are never read.
        let mut b = PatchBuilder::new();
        b.eof();
        let mut patch = b.bytes();
        patch.extend_from_slice(b"garbage that must be ignored");
        let mut reader = PatchReader::open(&patch[..]).unwrap();
        assert!(matches!(
            reader.next_chunk().unwrap(),
            Some(Chunk::EndOfFile)
        ));
        assert!(reader.next_chunk().unwrap().is_none());
        // Idempotent after the terminator.
        assert!(reader.next_chunk().unwrap().is_none());
    }

    proptest! {
        // Round-trip an AddData command over the full field space: build the bytes, parse them, and
        // the decoded target/offsets/data come back exactly. This exercises the big-endian reads and
        // the `<<7` expansion across arbitrary inputs, not one fixture.
        #[test]
        fn add_data_round_trips(
            main_id in any::<u16>(),
            sub_id in any::<u16>(),
            file_id in any::<u32>(),
            block_off in 0u32..=0x00FF_FFFF,
            block_num in 0u32..=64,          // keep the data slice small
            block_del in 0u32..=0x00FF_FFFF,
            fill in any::<u8>(),
        ) {
            let data_len = (block_num as usize) << 7;
            let mut a = Vec::new();
            a.extend_from_slice(&[0, 0, 0]);
            a.extend_from_slice(&target(main_id, sub_id, file_id));
            a.extend_from_slice(&bytes::write_u32_be(block_off));
            a.extend_from_slice(&bytes::write_u32_be(block_num));
            a.extend_from_slice(&bytes::write_u32_be(block_del));
            a.extend_from_slice(&vec![fill; data_len]);

            let mut b = PatchBuilder::new();
            b.sqpk(b'A', &a).eof();
            let patch = b.bytes();

            let mut reader = PatchReader::open(&patch[..]).unwrap();
            match reader.next_chunk().unwrap().unwrap() {
                Chunk::Sqpk(Sqpk::AddData(add)) => {
                    prop_assert_eq!(add.target, FileTarget { main_id, sub_id, file_id });
                    prop_assert_eq!(add.block_offset, u64::from(block_off) << 7);
                    prop_assert_eq!(add.block_size, u64::from(block_num) << 7);
                    prop_assert_eq!(add.block_delete_size, u64::from(block_del) << 7);
                    prop_assert_eq!(add.data.len(), data_len);
                }
                other => prop_assert!(false, "expected SQPK A, got {:?}", other),
            }
        }

        // The `<<7` expansion of any u32 stays within 40 bits — it can never overflow the u64 the
        // offsets are held in.
        #[test]
        fn shift_left_seven_never_overflows(x in any::<u32>()) {
            let widened = u64::from(x) << 7;
            prop_assert!(widened < (1u64 << 40));
        }
    }
}
