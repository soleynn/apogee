//! The `.apzi` on-disk block-index format (ours, version 1). A fixed 8-byte header
//! (`magic "APZI"`, `u16 version`, `u16 flags`) precedes a DEFLATE-compressed body; the `flags` low
//! byte names the body codec so a later version can switch without breaking the frame. Every
//! multi-byte field is big-endian through the crate's [`crate::bytes`] home.
//!
//! [`decode`] is a total, bounded, panic-free parser: the compressed input and the decompressed body
//! are both capped before allocation (hostile input, since a repair pulls the index over the
//! network), and every field read is a checked [`crate::bytes::Cursor`] read that yields a typed
//! [`Error::Truncated`]/[`Error::Corrupt`] rather than a panic.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

use crate::bytes::{self, Cursor};
use crate::chunk::Platform;
use crate::error::{Error, Limit, Op, Result};
use crate::index::model::{Index, Part, Source, SourcePatch, TargetFile};

/// The four-byte file magic.
const MAGIC: [u8; 4] = *b"APZI";
/// The only format version this build writes and reads.
const VERSION: u16 = 1;
/// The `flags` low-byte codec marker for a DEFLATE body.
const CODEC_DEFLATE: u16 = 1;

/// The cap on the compressed body read from the stream (bounds allocation on hostile input).
const MAX_COMPRESSED: u64 = 512 << 20;
/// The cap on the decompressed body (a full-game index is tens of MiB; this bounds a decompression
/// bomb well clear of any real index).
const MAX_DECOMPRESSED: u64 = 512 << 20;
/// The cap on any length-prefixed string (paths, patch names, the version label).
const MAX_STRING: u64 = 64 << 10;

/// Source-tag bytes for a [`Part`]'s [`Source`].
const TAG_PATCH: u8 = 0;
const TAG_ZEROS: u8 = 1;
const TAG_EMPTY: u8 = 2;
const TAG_UNAVAILABLE: u8 = 3;

impl Index {
    /// Serialize this index to `w` as an `.apzi` v1 file.
    ///
    /// # Errors
    /// [`Error::Io`] if the writer fails.
    pub fn write_apzi(&self, mut w: impl Write) -> Result<()> {
        let body = self.encode_body();
        let compressed = deflate(&body)?;
        let write = |e| io(e, Op::Write);
        w.write_all(&MAGIC).map_err(write)?;
        w.write_all(&bytes::write_u16_be(VERSION)).map_err(write)?;
        w.write_all(&bytes::write_u16_be(CODEC_DEFLATE))
            .map_err(write)?;
        w.write_all(&compressed).map_err(write)?;
        Ok(())
    }

    /// Parse an `.apzi` v1 file from `r`.
    ///
    /// # Errors
    /// [`Error::BadIndexMagic`] / [`Error::UnsupportedIndexVersion`] on a bad frame,
    /// [`Error::LimitExceeded`] if the body exceeds the decode cap, [`Error::Truncated`] /
    /// [`Error::Corrupt`] on a malformed body, [`Error::Io`] on a read fault.
    pub fn read_apzi(mut r: impl Read) -> Result<Index> {
        let mut header = [0u8; 8];
        r.read_exact(&mut header)
            .map_err(|_| Error::BadIndexMagic)?;
        if header[0..4] != MAGIC {
            return Err(Error::BadIndexMagic);
        }
        let version = bytes::u16_be([header[4], header[5]]);
        if version != VERSION {
            return Err(Error::UnsupportedIndexVersion { version });
        }
        let flags = bytes::u16_be([header[6], header[7]]);
        if flags & 0xFF != CODEC_DEFLATE {
            return Err(Error::Unsupported {
                what: "index body compression codec",
            });
        }

        let mut compressed = Vec::new();
        (&mut r)
            .take(MAX_COMPRESSED + 1)
            .read_to_end(&mut compressed)
            .map_err(|e| io(e, Op::Read))?;
        if compressed.len() as u64 > MAX_COMPRESSED {
            return Err(Error::LimitExceeded {
                what: Limit::IndexSize,
                value: compressed.len() as u64,
                max: MAX_COMPRESSED,
            });
        }
        let body = inflate(&compressed)?;
        decode_body(&body)
    }

    /// The uncompressed body: version/platform, the source list, then one record per target file.
    fn encode_body(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_str(&mut b, &self.repo_version);
        b.push(platform_byte(self.platform));
        put_u32(&mut b, self.sources.len() as u32);
        for src in &self.sources {
            put_str(&mut b, &src.name);
            put_u64(&mut b, src.expected_len);
        }
        put_u32(&mut b, self.targets.len() as u32);
        for tf in &self.targets {
            put_str(&mut b, &tf.path.to_string_lossy());
            put_u64(&mut b, tf.final_len());
            put_u32(&mut b, tf.parts.len() as u32);
            for part in &tf.parts {
                put_part(&mut b, part);
            }
        }
        b
    }
}

/// Encode one part: the target range, crc, then a tagged source.
fn put_part(b: &mut Vec<u8>, part: &Part) {
    put_u64(b, part.target_off);
    put_u64(b, part.target_len);
    put_u32(b, part.crc32);
    b.push(u8::from(part.crc_valid));
    match part.source {
        Source::Patch {
            idx,
            off,
            deflated,
            deflated_len,
            block_dlen,
            decoded_from,
        } => {
            b.push(TAG_PATCH);
            b.extend_from_slice(&bytes::write_u16_be(idx));
            put_u64(b, off);
            b.push(u8::from(deflated));
            put_u32(b, deflated_len);
            put_u32(b, block_dlen);
            put_u64(b, decoded_from);
        }
        Source::Zeros => b.push(TAG_ZEROS),
        Source::EmptyBlock {
            block_count,
            decoded_from,
        } => {
            b.push(TAG_EMPTY);
            put_u32(b, block_count);
            put_u64(b, decoded_from);
        }
        Source::Unavailable => b.push(TAG_UNAVAILABLE),
    }
}

/// Parse the decompressed body. Base offset `0`: `.apzi` offsets are body-relative, not patch-file
/// absolute, so a truncation reports where in the body it ran off the end.
fn decode_body(body: &[u8]) -> Result<Index> {
    let mut c = Cursor::new(body, 0);
    let repo_version = take_str(&mut c)?;
    let platform = platform_from_byte(c.u8()?)?;

    let source_count = c.u32_be()?;
    let mut sources = Vec::new();
    for _ in 0..source_count {
        let name = take_str(&mut c)?;
        let expected_len = c.u64_be()?;
        sources.push(SourcePatch { name, expected_len });
    }

    let target_count = c.u32_be()?;
    let mut targets = Vec::new();
    for _ in 0..target_count {
        let path = take_str(&mut c)?;
        let final_len = c.u64_be()?;
        let part_count = c.u32_be()?;
        let mut parts = Vec::new();
        // The parts must form the gapless, non-overlapping tiling of `[0, final_len)` the builder
        // always produces. Validating it here with checked arithmetic keeps every later consumer
        // (verify, reconstruct) free of unchecked offset math on hostile bytes, and rejects an
        // overflowing or malformed range as a typed error rather than a panic.
        let mut next_off = 0u64;
        for _ in 0..part_count {
            let part = take_part(&mut c)?;
            if part.target_off != next_off {
                return Err(Error::Corrupt {
                    offset: c.offset(),
                    detail: "index parts are not a gapless tiling from zero",
                });
            }
            next_off = part
                .target_off
                .checked_add(part.target_len)
                .ok_or(Error::Corrupt {
                    offset: c.offset(),
                    detail: "index part range overflows",
                })?;
            parts.push(part);
        }
        if next_off != final_len {
            return Err(Error::Corrupt {
                offset: c.offset(),
                detail: "index target final length disagrees with its parts",
            });
        }
        targets.push(TargetFile {
            path: path.into(),
            parts,
        });
    }

    Ok(Index {
        repo_version,
        platform,
        sources,
        targets,
    })
}

/// Parse one part.
fn take_part(c: &mut Cursor<'_>) -> Result<Part> {
    let target_off = c.u64_be()?;
    let target_len = c.u64_be()?;
    let crc32 = c.u32_be()?;
    let crc_valid = c.u8()? != 0;
    let tag = c.u8()?;
    let source = match tag {
        TAG_PATCH => Source::Patch {
            idx: c.u16_be()?,
            off: c.u64_be()?,
            deflated: c.u8()? != 0,
            deflated_len: c.u32_be()?,
            block_dlen: c.u32_be()?,
            decoded_from: c.u64_be()?,
        },
        TAG_ZEROS => Source::Zeros,
        TAG_EMPTY => Source::EmptyBlock {
            block_count: c.u32_be()?,
            decoded_from: c.u64_be()?,
        },
        TAG_UNAVAILABLE => Source::Unavailable,
        other => {
            return Err(Error::Corrupt {
                offset: c.offset(),
                detail: unknown_source_tag(other),
            });
        }
    };
    Ok(Part {
        target_off,
        target_len,
        source,
        crc32,
        crc_valid,
    })
}

/// A stable static detail string for an unknown source tag (the taxonomy carries `&'static str`).
fn unknown_source_tag(_tag: u8) -> &'static str {
    "unknown index part source tag"
}

fn put_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&bytes::write_u32_be(v));
}

fn put_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&bytes::write_u64_be(v));
}

/// Write a length-prefixed UTF-8 string (`u32` length, then bytes).
fn put_str(b: &mut Vec<u8>, s: &str) {
    put_u32(b, s.len() as u32);
    b.extend_from_slice(s.as_bytes());
}

/// Read a length-prefixed UTF-8 string, capping the length before allocation and rejecting invalid
/// UTF-8 as a typed corruption.
fn take_str(c: &mut Cursor<'_>) -> Result<String> {
    let len = u64::from(c.u32_be()?);
    if len > MAX_STRING {
        return Err(Error::LimitExceeded {
            what: Limit::IndexSize,
            value: len,
            max: MAX_STRING,
        });
    }
    let raw = c.take(len as usize)?;
    String::from_utf8(raw.to_vec()).map_err(|_| Error::Corrupt {
        offset: c.offset(),
        detail: "index string is not valid utf-8",
    })
}

fn platform_byte(p: Platform) -> u8 {
    match p {
        Platform::Win32 => 0,
        Platform::Ps3 => 1,
        Platform::Ps4 => 2,
    }
}

fn platform_from_byte(b: u8) -> Result<Platform> {
    Platform::from_u16(u16::from(b)).ok_or(Error::Corrupt {
        offset: 0,
        detail: "unknown index platform",
    })
}

/// DEFLATE-compress the body.
fn deflate(body: &[u8]) -> Result<Vec<u8>> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(body).map_err(|e| io(e, Op::Write))?;
    enc.finish().map_err(|e| io(e, Op::Write))
}

/// Inflate the body, capping the output before it can grow past [`MAX_DECOMPRESSED`].
fn inflate(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    DeflateDecoder::new(compressed)
        .take(MAX_DECOMPRESSED + 1)
        .read_to_end(&mut out)
        .map_err(|_| Error::Corrupt {
            offset: 0,
            detail: "index body failed to decompress",
        })?;
    if out.len() as u64 > MAX_DECOMPRESSED {
        return Err(Error::LimitExceeded {
            what: Limit::IndexSize,
            value: out.len() as u64,
            max: MAX_DECOMPRESSED,
        });
    }
    Ok(out)
}

fn io(source: std::io::Error, during: Op) -> Error {
    Error::Io {
        source,
        target: None,
        during,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small but representative index: stored, zeros, compressed, and empty-block parts across two
    /// files, so the round-trip exercises every source tag and both flag bits.
    fn sample_index() -> Index {
        Index {
            repo_version: "2024.01.01.0000.0000".to_owned(),
            platform: Platform::Win32,
            sources: vec![
                SourcePatch {
                    name: "D2024.01.01.0000.0000.patch".to_owned(),
                    expected_len: 4096,
                },
                SourcePatch {
                    name: "H2024.02.02.0000.0000.patch".to_owned(),
                    expected_len: 8192,
                },
            ],
            targets: vec![
                TargetFile {
                    path: "ffxivboot.exe".into(),
                    parts: vec![
                        Part {
                            target_off: 0,
                            target_len: 64,
                            source: Source::Patch {
                                idx: 0,
                                off: 200,
                                deflated: true,
                                deflated_len: 40,
                                block_dlen: 64,
                                decoded_from: 0,
                            },
                            crc32: 0x1234_5678,
                            crc_valid: true,
                        },
                        Part {
                            target_off: 64,
                            target_len: 512,
                            source: Source::EmptyBlock {
                                block_count: 4,
                                decoded_from: 0,
                            },
                            crc32: 0,
                            crc_valid: false,
                        },
                    ],
                },
                TargetFile {
                    path: "sqpack/ffxiv/0a0000.win32.dat0".into(),
                    parts: vec![
                        Part {
                            target_off: 0,
                            target_len: 128,
                            source: Source::Patch {
                                idx: 1,
                                off: 100,
                                deflated: false,
                                deflated_len: 0,
                                block_dlen: 0,
                                decoded_from: 0,
                            },
                            crc32: 0xDEAD_BEEF,
                            crc_valid: true,
                        },
                        Part {
                            target_off: 128,
                            target_len: 256,
                            source: Source::Zeros,
                            crc32: 0,
                            crc_valid: false,
                        },
                    ],
                },
            ],
        }
    }

    #[test]
    fn round_trips_every_source_tag() {
        let index = sample_index();
        let mut buf = Vec::new();
        index.write_apzi(&mut buf).expect("encode");
        assert_eq!(&buf[0..4], b"APZI");
        let back = Index::read_apzi(&buf[..]).expect("decode");
        assert_eq!(index, back);
    }

    #[test]
    fn a_bad_magic_is_rejected() {
        assert!(matches!(
            Index::read_apzi(b"not an index at all".as_slice()),
            Err(Error::BadIndexMagic)
        ));
        // A stream shorter than the 8-byte header is a bad magic too.
        assert!(matches!(
            Index::read_apzi([0x41, 0x50].as_slice()),
            Err(Error::BadIndexMagic)
        ));
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"APZI");
        buf.extend_from_slice(&bytes::write_u16_be(2)); // version 2
        buf.extend_from_slice(&bytes::write_u16_be(CODEC_DEFLATE));
        match Index::read_apzi(&buf[..]) {
            Err(Error::UnsupportedIndexVersion { version }) => assert_eq!(version, 2),
            other => panic!("expected UnsupportedIndexVersion, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_codec_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"APZI");
        buf.extend_from_slice(&bytes::write_u16_be(VERSION));
        buf.extend_from_slice(&bytes::write_u16_be(2)); // codec 2, not deflate
        assert!(matches!(
            Index::read_apzi(&buf[..]),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn a_garbage_body_is_a_typed_error_not_a_panic() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"APZI");
        buf.extend_from_slice(&bytes::write_u16_be(VERSION));
        buf.extend_from_slice(&bytes::write_u16_be(CODEC_DEFLATE));
        buf.extend_from_slice(&[0xFF, 0x00, 0xAB, 0xCD, 0x12]); // not a DEFLATE stream
        assert!(Index::read_apzi(&buf[..]).is_err());
    }

    #[test]
    fn a_truncated_body_is_a_typed_error_not_a_panic() {
        let index = sample_index();
        let mut buf = Vec::new();
        index.write_apzi(&mut buf).expect("encode");
        // Cut into the compressed body: decode must fault, never panic.
        buf.truncate(buf.len() - 3);
        assert!(Index::read_apzi(&buf[..]).is_err());
    }

    #[test]
    fn a_final_length_that_disagrees_with_its_parts_is_corrupt() {
        // Hand-encode a body whose stored final_len (999) does not match its single 128-byte part.
        let mut body = Vec::new();
        put_str(&mut body, "v");
        body.push(platform_byte(Platform::Win32));
        put_u32(&mut body, 0); // no sources
        put_u32(&mut body, 1); // one target
        put_str(&mut body, "a.dat");
        put_u64(&mut body, 999); // wrong final_len
        put_u32(&mut body, 1); // one part
        put_part(
            &mut body,
            &Part {
                target_off: 0,
                target_len: 128,
                source: Source::Zeros,
                crc32: 0,
                crc_valid: false,
            },
        );
        assert!(matches!(read_framed(&body), Err(Error::Corrupt { .. })));
    }

    /// Wrap a raw body in the `.apzi` frame and decode it.
    fn read_framed(body: &[u8]) -> Result<Index> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"APZI");
        buf.extend_from_slice(&bytes::write_u16_be(VERSION));
        buf.extend_from_slice(&bytes::write_u16_be(CODEC_DEFLATE));
        buf.extend_from_slice(&deflate(body).expect("deflate"));
        Index::read_apzi(&buf[..])
    }

    /// A minimal one-target body carrying a single `part`, with the (possibly wrong) `final_len`.
    fn one_part_body(final_len: u64, part: &Part) -> Vec<u8> {
        let mut body = Vec::new();
        put_str(&mut body, "v");
        body.push(platform_byte(Platform::Win32));
        put_u32(&mut body, 0); // no sources
        put_u32(&mut body, 1); // one target
        put_str(&mut body, "a.dat");
        put_u64(&mut body, final_len);
        put_u32(&mut body, 1); // one part
        put_part(&mut body, part);
        body
    }

    #[test]
    fn an_overflowing_part_range_is_corrupt_not_a_panic() {
        // A part whose target_off + target_len overflows u64 must decode to a typed error, never an
        // overflow panic (the deserializer is a fuzz target and must stay total).
        let body = one_part_body(
            0,
            &Part {
                target_off: u64::MAX,
                target_len: 1,
                source: Source::Zeros,
                crc32: 0,
                crc_valid: false,
            },
        );
        assert!(matches!(read_framed(&body), Err(Error::Corrupt { .. })));
    }

    #[test]
    fn a_non_gapless_tiling_is_corrupt() {
        // A single part that does not start at 0 leaves [0, off) uncovered: the tiling invariant the
        // builder guarantees is broken, so decode rejects it.
        let body = one_part_body(
            136,
            &Part {
                target_off: 8,
                target_len: 128,
                source: Source::Zeros,
                crc32: 0,
                crc_valid: false,
            },
        );
        assert!(matches!(read_framed(&body), Err(Error::Corrupt { .. })));
    }

    #[test]
    fn an_over_cap_string_is_rejected_before_allocation() {
        // The very first string (repo_version) claims a length past MAX_STRING: a bounded parser
        // rejects it with a limit error rather than trying to allocate it.
        let mut body = Vec::new();
        put_u32(&mut body, (MAX_STRING + 1) as u32);
        assert!(matches!(
            read_framed(&body),
            Err(Error::LimitExceeded {
                what: Limit::IndexSize,
                ..
            })
        ));
    }

    #[test]
    fn round_trips_an_unavailable_part() {
        // Unavailable parts only arise at repair time, but the format must still round-trip the tag.
        let index = Index {
            repo_version: "v".to_owned(),
            platform: Platform::Win32,
            sources: Vec::new(),
            targets: vec![TargetFile {
                path: "hole.dat".into(),
                parts: vec![Part {
                    target_off: 0,
                    target_len: 64,
                    source: Source::Unavailable,
                    crc32: 0,
                    crc_valid: false,
                }],
            }],
        };
        let mut buf = Vec::new();
        index.write_apzi(&mut buf).expect("encode");
        assert_eq!(Index::read_apzi(&buf[..]).expect("decode"), index);
    }
}
