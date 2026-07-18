//! The compressed-block codec: the on-disk SqPack block format, shared with `apogee-zipatch` so the
//! patcher that writes blocks and the reader that consumes them cannot drift. `F:A` patch payloads
//! are SqPack blocks in transit, which is why the one implementation lives here.
//!
//! A block is a 16-byte little-endian header followed by a payload, the whole run padded up to a
//! 128-byte boundary:
//!
//! ```text
//! u32le header_size (16)   u32le pad   u32le compressed_size   u32le decompressed_size   payload…  pad…
//! ```
//!
//! `compressed_size == 0x7D00` is the sentinel for a stored (uncompressed) block: the payload is
//! `decompressed_size` raw bytes. Otherwise the payload is `compressed_size` bytes of raw DEFLATE
//! (no zlib wrapper). Every block occupies `ceil((payload + 16) / 128) * 128` bytes on disk.

use std::io::{self, Read, Write};

use crate::bytes;
use crate::error::{Error, Result};

/// The fixed byte length of a block header.
pub const BLOCK_HEADER_LEN: u32 = 16;

/// The `compressed_size` value that marks a stored (uncompressed) block instead of a DEFLATE payload.
pub const STORED_SENTINEL: u32 = 0x7D00;

/// A conservative default cap on a single block's decompressed size. Real SqPack data blocks top out
/// at 16 KiB; callers with a different bound set their own [`Limits`].
pub const DEFAULT_MAX_DECOMPRESSED: u32 = 1 << 20;

/// A parsed, validated 16-byte little-endian block header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    /// The header's own length. Always [`BLOCK_HEADER_LEN`]; parsing rejects any other value.
    pub header_size: u32,
    /// The DEFLATE payload length, or [`STORED_SENTINEL`] for a stored block.
    pub compressed_size: u32,
    /// The block's size once decoded.
    pub decompressed_size: u32,
}

impl BlockHeader {
    /// Whether the block is stored (uncompressed) rather than DEFLATE-compressed.
    #[must_use]
    pub fn is_stored(&self) -> bool {
        self.compressed_size == STORED_SENTINEL
    }

    /// Whether the block carries a DEFLATE payload.
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        !self.is_stored()
    }
}

/// What [`read_block`] produced, including the number of bytes it consumed from the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockMeta {
    /// The header's `compressed_size` field ([`STORED_SENTINEL`] for a stored block).
    pub compressed_size: u32,
    /// The decoded byte count written to the output.
    pub decompressed_size: u32,
    /// Whether the block was DEFLATE-compressed.
    pub is_compressed: bool,
    /// Total bytes consumed from the source: header plus payload plus 128-byte-boundary padding. A
    /// caller streaming back-to-back blocks (the `F:A` case) advances by exactly this much.
    pub block_len: u32,
}

/// Allocation bounds enforced while decoding a block (all SqPack input is hostile).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Reject any block whose declared `decompressed_size` exceeds this.
    pub max_decompressed: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_decompressed: DEFAULT_MAX_DECOMPRESSED,
        }
    }
}

/// The on-disk footprint of a block whose payload is `payload` bytes: `ceil((payload + 16) / 128)`
/// rounded to 128. `None` only when `payload + 143` would overflow a `u32`.
#[must_use]
pub fn padded_block_len(payload: u32) -> Option<u32> {
    Some(payload.checked_add(143)? & !0x7F)
}

/// Parse a 16-byte block header, rejecting any header that does not declare its own length as 16.
///
/// # Errors
/// [`Error::BlockCorrupt`] if `header_size` is not [`BLOCK_HEADER_LEN`].
pub fn parse_header(bytes_in: &[u8; 16]) -> Result<BlockHeader> {
    let header_size = bytes::u32_le([bytes_in[0], bytes_in[1], bytes_in[2], bytes_in[3]]);
    // bytes_in[4..8] is padding, always read and discarded.
    let compressed_size = bytes::u32_le([bytes_in[8], bytes_in[9], bytes_in[10], bytes_in[11]]);
    let decompressed_size = bytes::u32_le([bytes_in[12], bytes_in[13], bytes_in[14], bytes_in[15]]);

    if header_size != BLOCK_HEADER_LEN {
        return Err(Error::BlockCorrupt {
            offset: 0,
            detail: "unexpected block header size",
        });
    }
    Ok(BlockHeader {
        header_size,
        compressed_size,
        decompressed_size,
    })
}

/// Decode one block from `src` into `out`, bounded by `limits`.
///
/// Consumes exactly [`BlockMeta::block_len`] bytes from `src` (header, payload, and padding), writes
/// exactly `decompressed_size` bytes to `out`, and validates that the DEFLATE stream produces neither
/// more nor fewer bytes than declared. Errors carry offsets relative to the start of the block.
///
/// # Errors
/// - [`Error::Truncated`] if `src` ends before a full block is read.
/// - [`Error::LimitExceeded`] if the declared `decompressed_size` exceeds `limits.max_decompressed`.
/// - [`Error::BlockCorrupt`] on a malformed header, an out-of-range compressed size, or a DEFLATE
///   stream that does not decode to exactly `decompressed_size` bytes.
/// - [`Error::Io`] if `out` fails to accept the decoded bytes.
pub fn read_block(src: &mut impl Read, out: &mut impl Write, limits: &Limits) -> Result<BlockMeta> {
    let mut header_bytes = [0u8; BLOCK_HEADER_LEN as usize];
    read_full(src, &mut header_bytes, 0)?;
    let header = parse_header(&header_bytes)?;

    let compressed_size = header.compressed_size;
    let decompressed_size = header.decompressed_size;
    let is_compressed = header.is_compressed();

    if decompressed_size > limits.max_decompressed {
        return Err(Error::LimitExceeded);
    }

    let payload = if is_compressed {
        // A compressed block's size is always below the stored sentinel; anything else is corrupt and
        // would otherwise let a hostile header demand an unbounded read.
        if compressed_size > STORED_SENTINEL {
            return Err(Error::BlockCorrupt {
                offset: 8,
                detail: "compressed size exceeds stored sentinel",
            });
        }
        compressed_size
    } else {
        decompressed_size
    };

    let block_len = padded_block_len(payload).ok_or(Error::BlockCorrupt {
        offset: 0,
        detail: "block length overflow",
    })?;
    let region_len = block_len - BLOCK_HEADER_LEN;
    let pad_len = region_len - payload;

    if is_compressed {
        let mut compressed = vec![0u8; compressed_size as usize];
        read_full(src, &mut compressed, u64::from(BLOCK_HEADER_LEN))?;
        inflate_bounded(&compressed, out, decompressed_size)?;
    } else {
        copy_exact(
            src,
            out,
            u64::from(decompressed_size),
            u64::from(BLOCK_HEADER_LEN),
        )?;
    }
    skip_exact(
        src,
        u64::from(pad_len),
        u64::from(BLOCK_HEADER_LEN) + u64::from(payload),
    )?;

    Ok(BlockMeta {
        compressed_size,
        decompressed_size,
        is_compressed,
        block_len,
    })
}

/// Read exactly `buf.len()` bytes, mapping a short read to a typed truncation at `offset`.
fn read_full(src: &mut impl Read, buf: &mut [u8], offset: u64) -> Result<()> {
    match src.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(Error::Truncated {
            offset,
            needed: buf.len() as u64,
        }),
        Err(err) => Err(Error::Io(err)),
    }
}

/// Copy exactly `n` bytes from `src` to `out`, erroring if `src` runs short.
fn copy_exact(src: &mut impl Read, out: &mut impl Write, n: u64, offset: u64) -> Result<()> {
    let copied = io::copy(&mut src.by_ref().take(n), out)?;
    if copied != n {
        return Err(Error::Truncated {
            offset: offset + copied,
            needed: n - copied,
        });
    }
    Ok(())
}

/// Discard exactly `n` bytes from `src`, erroring if `src` runs short.
fn skip_exact(src: &mut impl Read, n: u64, offset: u64) -> Result<()> {
    let skipped = io::copy(&mut src.by_ref().take(n), &mut io::sink())?;
    if skipped != n {
        return Err(Error::Truncated {
            offset: offset + skipped,
            needed: n - skipped,
        });
    }
    Ok(())
}

/// DEFLATE-decode `compressed` into `out`, requiring exactly `expected` output bytes. The output is
/// capped as it is produced, so a stream that inflates past `expected` is rejected rather than
/// allocated.
fn inflate_bounded(compressed: &[u8], out: &mut impl Write, expected: u32) -> Result<()> {
    let mut decoder = flate2::read::DeflateDecoder::new(compressed);
    let expected = expected as usize;
    let mut written = 0usize;
    let mut buf = [0u8; 8192];
    loop {
        // Once the expected count is reached, probe for a single extra byte to detect overrun.
        let want = if written < expected {
            (expected - written).min(buf.len())
        } else {
            1
        };
        let n = decoder
            .read(&mut buf[..want])
            .map_err(|_| Error::BlockCorrupt {
                offset: u64::from(BLOCK_HEADER_LEN),
                detail: "deflate decode failed",
            })?;
        if n == 0 {
            break;
        }
        written += n;
        if written > expected {
            return Err(Error::BlockCorrupt {
                offset: u64::from(BLOCK_HEADER_LEN),
                detail: "decompressed size exceeds declared",
            });
        }
        out.write_all(&buf[..n])?;
    }
    if written != expected {
        return Err(Error::BlockCorrupt {
            offset: u64::from(BLOCK_HEADER_LEN),
            detail: "decompressed size below declared",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    /// Raw-DEFLATE-compress `plain` the way SqPack stores a compressed block (no zlib wrapper).
    fn deflate(plain: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).unwrap();
        encoder.finish().unwrap()
    }

    /// Build a block's on-disk bytes from an already-chosen `compressed_size` (or the sentinel) and a
    /// payload, padding the whole run to the 128-byte boundary.
    fn block_bytes(compressed_size: u32, decompressed_size: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&bytes::write_u32_le(BLOCK_HEADER_LEN));
        out.extend_from_slice(&bytes::write_u32_le(0)); // pad
        out.extend_from_slice(&bytes::write_u32_le(compressed_size));
        out.extend_from_slice(&bytes::write_u32_le(decompressed_size));
        out.extend_from_slice(payload);
        let indicator = if compressed_size == STORED_SENTINEL {
            decompressed_size
        } else {
            compressed_size
        };
        let total = padded_block_len(indicator).unwrap() as usize;
        out.resize(total, 0);
        out
    }

    /// A stored block from raw bytes.
    fn stored_block(plain: &[u8]) -> Vec<u8> {
        block_bytes(STORED_SENTINEL, plain.len() as u32, plain)
    }

    /// A compressed block from raw bytes.
    fn compressed_block(plain: &[u8]) -> Vec<u8> {
        let deflated = deflate(plain);
        block_bytes(deflated.len() as u32, plain.len() as u32, &deflated)
    }

    fn decode(block: &[u8], limits: &Limits) -> Result<(Vec<u8>, BlockMeta)> {
        let mut src = block;
        let mut out = Vec::new();
        let meta = read_block(&mut src, &mut out, limits)?;
        Ok((out, meta))
    }

    #[test]
    fn header_fields_are_little_endian() {
        // A byte-for-byte pin of the header layout: header_size=16, pad=0, compressed=0x7D00,
        // decompressed=0x1234.
        let header: [u8; 16] = [
            0x10, 0x00, 0x00, 0x00, // header_size = 16
            0x00, 0x00, 0x00, 0x00, // pad
            0x00, 0x7d, 0x00, 0x00, // compressed_size = 0x7D00 (stored sentinel)
            0x34, 0x12, 0x00, 0x00, // decompressed_size = 0x1234
        ];
        let parsed = parse_header(&header).unwrap();
        assert_eq!(parsed.header_size, 16);
        assert_eq!(parsed.compressed_size, STORED_SENTINEL);
        assert_eq!(parsed.decompressed_size, 0x1234);
        assert!(parsed.is_stored());
        assert!(!parsed.is_compressed());
    }

    #[test]
    fn parse_header_rejects_wrong_header_size() {
        let mut header = [0u8; 16];
        header[0] = 0x20; // header_size = 32
        header[8..12].copy_from_slice(&bytes::write_u32_le(STORED_SENTINEL));
        assert!(matches!(
            parse_header(&header),
            Err(Error::BlockCorrupt { detail, .. }) if detail == "unexpected block header size"
        ));
    }

    #[test]
    fn padded_len_rounds_up_to_128() {
        // ceil((payload + 16) / 128) * 128.
        assert_eq!(padded_block_len(0), Some(128));
        assert_eq!(padded_block_len(111), Some(128)); // 111 + 16 = 127 -> 128
        assert_eq!(padded_block_len(112), Some(128)); // 112 + 16 = 128 -> 128
        assert_eq!(padded_block_len(113), Some(256)); // 113 + 16 = 129 -> 256
        assert_eq!(padded_block_len(240), Some(256));
        assert_eq!(padded_block_len(241), Some(384));
        assert_eq!(padded_block_len(u32::MAX), None); // overflow guard
    }

    #[test]
    fn stored_block_round_trips() {
        let plain = b"the quick brown fox".to_vec();
        let block = stored_block(&plain);
        let (out, meta) = decode(&block, &Limits::default()).unwrap();
        assert_eq!(out, plain);
        assert!(!meta.is_compressed);
        assert_eq!(meta.compressed_size, STORED_SENTINEL);
        assert_eq!(meta.decompressed_size, plain.len() as u32);
        assert_eq!(meta.block_len as usize, block.len());
    }

    #[test]
    fn compressed_block_round_trips() {
        let plain = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let block = compressed_block(&plain);
        let (out, meta) = decode(&block, &Limits::default()).unwrap();
        assert_eq!(out, plain);
        assert!(meta.is_compressed);
        assert!(meta.compressed_size < STORED_SENTINEL);
        assert_eq!(meta.decompressed_size, plain.len() as u32);
        assert_eq!(meta.block_len as usize, block.len());
    }

    #[test]
    fn empty_stored_block_is_one_padded_unit() {
        let block = stored_block(b"");
        let (out, meta) = decode(&block, &Limits::default()).unwrap();
        assert!(out.is_empty());
        assert_eq!(meta.block_len, 128);
        assert_eq!(block.len(), 128);
    }

    #[test]
    fn compressed_block_spanning_the_inflate_buffer_round_trips() {
        // A block that decodes well past the 8 KiB refill buffer, exercising inflate_bounded's
        // multi-read loop (the real 16 KiB-block path). The payload is highly compressible, so
        // compressed_size stays far below the stored sentinel.
        let plain: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let block = compressed_block(&plain);
        let (out, meta) = decode(&block, &Limits::default()).unwrap();
        assert_eq!(out, plain);
        assert!(meta.is_compressed);
        assert!(meta.compressed_size < STORED_SENTINEL);
        assert_eq!(meta.decompressed_size, 20_000);
        assert_eq!(meta.block_len as usize, block.len());
    }

    #[test]
    fn stored_block_spanning_multiple_padding_units() {
        // payload 200 -> ceil((200 + 16) / 128) * 128 = 256: header 16 + payload 200 + pad 40.
        let plain: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let block = stored_block(&plain);
        assert_eq!(block.len(), 256);
        let (out, meta) = decode(&block, &Limits::default()).unwrap();
        assert_eq!(out, plain);
        assert_eq!(meta.block_len, 256);
    }

    #[test]
    fn stored_block_landing_exactly_on_a_unit_boundary_has_no_padding() {
        // payload 240 -> 240 + 16 = 256, a whole unit: pad_len is zero, so the next block would start
        // immediately. Two such blocks back to back must align exactly.
        let a: Vec<u8> = (0..240u32).map(|i| i as u8).collect();
        let b: Vec<u8> = (0..240u32).map(|i| (i ^ 0xAA) as u8).collect();
        let block_a = stored_block(&a);
        let block_b = stored_block(&b);
        assert_eq!(block_a.len(), 256);
        assert_eq!(padded_block_len(240), Some(256)); // pad_len = 256 - 16 - 240 = 0

        let mut joined = block_a.clone();
        joined.extend_from_slice(&block_b);
        let mut src: &[u8] = &joined;
        let mut out_a = Vec::new();
        read_block(&mut src, &mut out_a, &Limits::default()).unwrap();
        let mut out_b = Vec::new();
        read_block(&mut src, &mut out_b, &Limits::default()).unwrap();
        assert_eq!(out_a, a);
        assert_eq!(out_b, b);
        assert!(src.is_empty());
    }

    #[test]
    fn two_blocks_stream_back_to_back() {
        // The F:A case: blocks packed with no separators. Decoding advances by block_len each time.
        let first = compressed_block(b"first block contents, compressible padding padding padding");
        let second = stored_block(b"second block, stored verbatim");
        let mut joined = first.clone();
        joined.extend_from_slice(&second);

        let mut src: &[u8] = &joined;
        let mut out1 = Vec::new();
        let meta1 = read_block(&mut src, &mut out1, &Limits::default()).unwrap();
        assert_eq!(
            out1,
            b"first block contents, compressible padding padding padding"
        );
        assert_eq!(meta1.block_len as usize, first.len());

        let mut out2 = Vec::new();
        let meta2 = read_block(&mut src, &mut out2, &Limits::default()).unwrap();
        assert_eq!(out2, b"second block, stored verbatim");
        assert_eq!(meta2.block_len as usize, second.len());
        assert!(src.is_empty());
    }

    #[test]
    fn decompressed_size_over_limit_is_rejected() {
        let block = stored_block(b"0123456789");
        let limits = Limits {
            max_decompressed: 4,
        };
        assert!(matches!(decode(&block, &limits), Err(Error::LimitExceeded)));
    }

    #[test]
    fn compressed_size_above_sentinel_is_corrupt() {
        // A "compressed" header (compressed_size != sentinel) whose size sits above the sentinel is a
        // hostile framing that would otherwise demand an unbounded read. Decoding rejects it after the
        // header, before touching the payload, so a bare header is enough to exercise it.
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&bytes::write_u32_le(BLOCK_HEADER_LEN));
        header[8..12].copy_from_slice(&bytes::write_u32_le(0x8000)); // compressed_size above sentinel
        header[12..16].copy_from_slice(&bytes::write_u32_le(4));
        assert!(matches!(
            decode(&header, &Limits::default()),
            Err(Error::BlockCorrupt { detail, .. }) if detail == "compressed size exceeds stored sentinel"
        ));
    }

    #[test]
    fn truncated_header_is_truncated_error() {
        let block = stored_block(b"payload");
        let short = &block[..10];
        assert!(matches!(
            decode(short, &Limits::default()),
            Err(Error::Truncated { offset: 0, .. })
        ));
    }

    #[test]
    fn truncated_payload_is_truncated_error() {
        let block = compressed_block(b"some compressible content content content");
        // Cut into the payload region, past the 16-byte header.
        let short = &block[..20];
        assert!(matches!(
            decode(short, &Limits::default()),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn garbage_deflate_is_block_corrupt() {
        // A well-framed compressed block whose payload is not valid DEFLATE.
        let garbage = [0xffu8; 32];
        let block = block_bytes(garbage.len() as u32, 64, &garbage);
        assert!(matches!(
            decode(&block, &Limits::default()),
            Err(Error::BlockCorrupt { .. })
        ));
    }

    #[test]
    fn deflate_shorter_than_declared_is_corrupt() {
        // Compress 8 bytes but claim 9 decompressed.
        let deflated = deflate(b"abcdefgh");
        let block = block_bytes(deflated.len() as u32, 9, &deflated);
        assert!(matches!(
            decode(&block, &Limits::default()),
            Err(Error::BlockCorrupt { detail, .. }) if detail == "decompressed size below declared"
        ));
    }

    #[test]
    fn deflate_longer_than_declared_is_corrupt() {
        // Compress 8 bytes but claim only 4 decompressed.
        let deflated = deflate(b"abcdefgh");
        let block = block_bytes(deflated.len() as u32, 4, &deflated);
        assert!(matches!(
            decode(&block, &Limits::default()),
            Err(Error::BlockCorrupt { detail, .. }) if detail == "decompressed size exceeds declared"
        ));
    }
}
