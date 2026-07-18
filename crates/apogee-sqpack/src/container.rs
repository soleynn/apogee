//! The SqPack common header: the first 1024 bytes shared by every `.index`/`.index2`/`.dat` file.
//!
//! Parsing here reaches only the small identifying prefix (magic, platform, size, version, type). The
//! header's SHA-1 self-hash at offset `0x3C0` is verified by the inspector, not on every open, so it
//! is deliberately not touched here.

use crate::bytes;
use crate::error::{Error, Result};

/// The 8-byte magic every SqPack file starts with.
pub const SQPACK_MAGIC: [u8; 8] = *b"SqPack\0\0";

/// The number of leading bytes [`parse_common_header`] needs (through the type field at `0x14`).
pub const COMMON_HEADER_MIN: usize = 0x18;

/// The full common-header length: the first block of every SqPack file.
pub const COMMON_HEADER_LEN: usize = 0x400;

/// The target platform a SqPack file was built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Platform {
    /// Windows (the only platform Apogee reads).
    Win32,
    /// PlayStation 3 (recognized, unsupported).
    Ps3,
    /// PlayStation 4 (recognized, unsupported).
    Ps4,
}

impl Platform {
    /// Map the platform byte at header offset `0x08`.
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Platform::Win32),
            1 => Ok(Platform::Ps3),
            2 => Ok(Platform::Ps4),
            _ => Err(Error::UnsupportedPlatform),
        }
    }

    /// Whether Apogee can read archives built for this platform.
    #[must_use]
    pub fn is_supported(self) -> bool {
        matches!(self, Platform::Win32)
    }
}

/// What kind of SqPack file a common header belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SqPackKind {
    /// An sqdb file (`type` 0). Recognized; the launcher never reads one.
    Sqdb,
    /// A data (`.dat`) file (`type` 1).
    Data,
    /// An index (`.index`/`.index2`) file (`type` 2).
    Index,
    /// A `type` value outside the known set, carried verbatim for the inspector to judge.
    Unknown(u32),
}

impl SqPackKind {
    fn from_u32(v: u32) -> Self {
        match v {
            0 => SqPackKind::Sqdb,
            1 => SqPackKind::Data,
            2 => SqPackKind::Index,
            other => SqPackKind::Unknown(other),
        }
    }
}

/// The parsed identifying prefix of a SqPack file. `header_size` and `version` are recorded as-read
/// (expected `0x400` and `1`); the inspector checks them, this does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonHeader {
    /// The target platform.
    pub platform: Platform,
    /// The declared header length (expected `0x400`).
    pub header_size: u32,
    /// The declared format version (expected `1`).
    pub version: u32,
    /// Which kind of SqPack file this is.
    pub kind: SqPackKind,
}

/// Parse the identifying fields of a SqPack common header.
///
/// # Errors
/// - [`Error::Truncated`] if fewer than [`COMMON_HEADER_MIN`] bytes are available.
/// - [`Error::BadMagic`] if the leading magic is wrong.
/// - [`Error::UnsupportedPlatform`] if the platform byte is not a recognized value.
pub fn parse_common_header(buf: &[u8]) -> Result<CommonHeader> {
    if buf.len() < COMMON_HEADER_MIN {
        return Err(Error::Truncated {
            offset: buf.len() as u64,
            needed: (COMMON_HEADER_MIN - buf.len()) as u64,
        });
    }
    if buf[0..8] != SQPACK_MAGIC {
        return Err(Error::BadMagic);
    }
    let platform = Platform::from_byte(buf[0x08])?;
    let header_size = bytes::read_u32_le(buf, 0x0C);
    let version = bytes::read_u32_le(buf, 0x10);
    let kind = SqPackKind::from_u32(bytes::read_u32_le(buf, 0x14));
    Ok(CommonHeader {
        platform,
        header_size,
        version,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a full 1024-byte common header with the given platform/type bytes and the standard
    /// `header_size`/`version`.
    fn common_header(platform: u8, kind: u32) -> Vec<u8> {
        let mut buf = vec![0u8; COMMON_HEADER_LEN];
        buf[0..8].copy_from_slice(&SQPACK_MAGIC);
        buf[0x08] = platform;
        buf[0x0C..0x10].copy_from_slice(&bytes::write_u32_le(0x400));
        buf[0x10..0x14].copy_from_slice(&bytes::write_u32_le(1));
        buf[0x14..0x18].copy_from_slice(&bytes::write_u32_le(kind));
        buf
    }

    #[test]
    fn parses_a_win32_index_header() {
        let buf = common_header(0, 2);
        let header = parse_common_header(&buf).unwrap();
        assert_eq!(header.platform, Platform::Win32);
        assert!(header.platform.is_supported());
        assert_eq!(header.header_size, 0x400);
        assert_eq!(header.version, 1);
        assert_eq!(header.kind, SqPackKind::Index);
    }

    #[test]
    fn recognizes_dat_and_sqdb_types() {
        assert_eq!(
            parse_common_header(&common_header(0, 1)).unwrap().kind,
            SqPackKind::Data
        );
        assert_eq!(
            parse_common_header(&common_header(0, 0)).unwrap().kind,
            SqPackKind::Sqdb
        );
    }

    #[test]
    fn carries_unknown_type_verbatim() {
        assert_eq!(
            parse_common_header(&common_header(0, 9)).unwrap().kind,
            SqPackKind::Unknown(9)
        );
    }

    #[test]
    fn carries_nonstandard_size_and_version_verbatim() {
        // header_size and version are recorded, never rejected; the inspector judges them later.
        let mut buf = common_header(0, 2);
        buf[0x0C..0x10].copy_from_slice(&bytes::write_u32_le(0x800));
        buf[0x10..0x14].copy_from_slice(&bytes::write_u32_le(7));
        let header = parse_common_header(&buf).unwrap();
        assert_eq!(header.header_size, 0x800);
        assert_eq!(header.version, 7);
    }

    #[test]
    fn recognizes_console_platforms_but_marks_them_unsupported() {
        let ps3 = parse_common_header(&common_header(1, 2)).unwrap();
        assert_eq!(ps3.platform, Platform::Ps3);
        assert!(!ps3.platform.is_supported());
        let ps4 = parse_common_header(&common_header(2, 2)).unwrap();
        assert_eq!(ps4.platform, Platform::Ps4);
        assert!(!ps4.platform.is_supported());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = common_header(0, 2);
        buf[3] = b'X';
        assert!(matches!(parse_common_header(&buf), Err(Error::BadMagic)));
    }

    #[test]
    fn rejects_unknown_platform_byte() {
        assert!(matches!(
            parse_common_header(&common_header(7, 2)),
            Err(Error::UnsupportedPlatform)
        ));
    }

    #[test]
    fn rejects_a_short_buffer() {
        let buf = common_header(0, 2);
        assert!(matches!(
            parse_common_header(&buf[..0x10]),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn header_prefix_byte_pin() {
        // A byte-for-byte pin of the little-endian prefix: magic, platform=win32, header_size=0x400,
        // version=1, type=index.
        let buf = common_header(0, 2);
        assert_eq!(
            &buf[0..0x18],
            &[
                b'S', b'q', b'P', b'a', b'c', b'k', 0x00, 0x00, // magic
                0x00, 0x00, 0x00, 0x00, // platform=win32 + 3 pad
                0x00, 0x04, 0x00, 0x00, // header_size = 0x400
                0x01, 0x00, 0x00, 0x00, // version = 1
                0x02, 0x00, 0x00, 0x00, // type = 2 (index)
            ]
        );
    }
}
