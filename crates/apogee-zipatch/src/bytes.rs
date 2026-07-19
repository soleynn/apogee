//! The one endianness home. Every `from_*_bytes`/`to_*_bytes` in the crate lives here, behind named
//! big- and little-endian helpers, so a field can't be read in the wrong order by accident.
//!
//! ZiPatch is the launcher's foot-gun format: chunk framing and most command fields are big-endian
//! (patcher-native), while a handful of fields are little-endian (game-native) — the `FHDR` version
//! dword read via a little-endian `ReadUInt32`, and the `T` command's `u64` sizes. The compressed-
//! block header is little-endian too, but it belongs to the shared SqPack codec. The empty-block
//! header the write-side shim ([`crate::datfile`]) stamps is also little-endian and is built through
//! the [`write_u32_le`]/[`write_u64_le`] helpers here, so the one endianness home covers it and the
//! audit gate stays satisfied. Every field's endianness is spelled out at its read site through these
//! helpers, and a per-field byte golden pins it.
//!
//! [`Cursor`] is the forward-only reader over one already-buffered chunk payload: every read is
//! bounds-checked and a short read becomes an [`Error::Truncated`] carrying the absolute file offset
//! of the field that ran off the end.

use crate::error::{Error, Result};

/// Read a `u16` from two big-endian bytes.
#[must_use]
pub fn u16_be(bytes: [u8; 2]) -> u16 {
    u16::from_be_bytes(bytes)
}

/// Read an `i16` from two big-endian bytes.
#[must_use]
pub fn i16_be(bytes: [u8; 2]) -> i16 {
    i16::from_be_bytes(bytes)
}

/// Read a `u32` from four big-endian bytes.
#[must_use]
pub fn u32_be(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

/// Read an `i64` from eight big-endian bytes.
#[must_use]
pub fn i64_be(bytes: [u8; 8]) -> i64 {
    i64::from_be_bytes(bytes)
}

/// Read a `u64` from eight big-endian bytes.
#[must_use]
pub fn u64_be(bytes: [u8; 8]) -> u64 {
    u64::from_be_bytes(bytes)
}

/// Read a `u32` from four little-endian bytes (the `FHDR` version dword; game-native fields).
#[must_use]
pub fn u32_le(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

/// Read a `u64` from eight little-endian bytes (the `T` command's `deletedDataSize`/`seekCount`).
#[must_use]
pub fn u64_le(bytes: [u8; 8]) -> u64 {
    u64::from_le_bytes(bytes)
}

/// Write a `u16` as two big-endian bytes (the `.apzi` version/flags words; test fixtures too).
#[must_use]
pub(crate) fn write_u16_be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

/// Write a `u32` as four big-endian bytes (the `.apzi` counts/crc/len fields).
#[must_use]
pub(crate) fn write_u32_be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// Write an `i64` as eight big-endian bytes. Used only by the test patch builders.
#[cfg(test)]
#[must_use]
pub fn write_i64_be(v: i64) -> [u8; 8] {
    v.to_be_bytes()
}

/// Write a `u64` as eight big-endian bytes (the `.apzi` offset/length fields).
#[must_use]
pub(crate) fn write_u64_be(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

/// Write a `u32` as four little-endian bytes. The empty-block write-side shim stamps its header
/// through this, so a game-native field can't be written in the wrong order by accident.
#[must_use]
pub(crate) fn write_u32_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Write a `u64` as eight little-endian bytes (the empty-block header's `blockCount - 1` field).
#[must_use]
pub(crate) fn write_u64_le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

/// A forward-only reader over one buffered chunk payload. It never allocates and never reads past the
/// end: a short read is an [`Error::Truncated`] whose `offset` is the absolute patch-file position of
/// the field, not a slice-relative one, so the taxonomy's triage promise holds.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Absolute patch-file offset of `buf[0]`, so reported offsets point into the real file.
    base: u64,
}

impl<'a> Cursor<'a> {
    /// A cursor over `buf`, whose byte 0 sits at absolute file offset `base`.
    #[must_use]
    pub fn new(buf: &'a [u8], base: u64) -> Self {
        Self { buf, pos: 0, base }
    }

    /// The absolute patch-file offset of the next unread byte.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.base + self.pos as u64
    }

    /// How many bytes remain unread.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Reserve `n` bytes at the cursor, returning their start index or a truncation error anchored at
    /// the current absolute offset.
    fn window(&self, n: usize) -> Result<usize> {
        if self.remaining() < n {
            return Err(Error::Truncated {
                offset: self.offset(),
                needed: (n - self.remaining()) as u64,
            });
        }
        Ok(self.pos)
    }

    /// Read a fixed-size array, advancing the cursor.
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let start = self.window(N)?;
        // `window` guaranteed N bytes; the slice is exactly N long, so the conversion cannot fail.
        let out = <[u8; N]>::try_from(&self.buf[start..start + N]).map_err(|_| Error::Corrupt {
            offset: self.offset(),
            detail: "array conversion",
        })?;
        self.pos += N;
        Ok(out)
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    /// Read a big-endian `u16`.
    pub fn u16_be(&mut self) -> Result<u16> {
        Ok(u16_be(self.array()?))
    }

    /// Read a big-endian `i16`.
    pub fn i16_be(&mut self) -> Result<i16> {
        Ok(i16_be(self.array()?))
    }

    /// Read a big-endian `u32`.
    pub fn u32_be(&mut self) -> Result<u32> {
        Ok(u32_be(self.array()?))
    }

    /// Read a big-endian `i64`.
    pub fn i64_be(&mut self) -> Result<i64> {
        Ok(i64_be(self.array()?))
    }

    /// Read a big-endian `u64`.
    pub fn u64_be(&mut self) -> Result<u64> {
        Ok(u64_be(self.array()?))
    }

    /// Read a little-endian `u32`.
    pub fn u32_le(&mut self) -> Result<u32> {
        Ok(u32_le(self.array()?))
    }

    /// Read a little-endian `u64`.
    pub fn u64_le(&mut self) -> Result<u64> {
        Ok(u64_le(self.array()?))
    }

    /// Skip `n` bytes (alignment padding, reserved fields), erroring if fewer remain.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        let start = self.window(n)?;
        self.pos = start + n;
        Ok(())
    }

    /// Borrow the next `n` bytes without copying, advancing the cursor.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let start = self.window(n)?;
        self.pos += n;
        Ok(&self.buf[start..start + n])
    }

    /// Borrow everything left, advancing to the end (the `F:A` compressed-block tail).
    pub fn rest(&mut self) -> &'a [u8] {
        let start = self.pos;
        self.pos = self.buf.len();
        &self.buf[start..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_and_little_endian_disagree_on_order() {
        assert_eq!(u32_be([0x11, 0x22, 0x33, 0x44]), 0x1122_3344);
        assert_eq!(u32_le([0x11, 0x22, 0x33, 0x44]), 0x4433_2211);
        assert_eq!(u16_be([0xAB, 0xCD]), 0xABCD);
        assert_eq!(i16_be([0xFF, 0xFF]), -1);
        assert_eq!(u64_be([0, 0, 0, 0, 0, 0, 0, 1]), 1);
        assert_eq!(u64_le([1, 0, 0, 0, 0, 0, 0, 0]), 1);
        assert_eq!(i64_be([0xFF; 8]), -1);
    }

    #[test]
    fn writers_invert_readers() {
        assert_eq!(u32_be(write_u32_be(0xdead_beef)), 0xdead_beef);
        assert_eq!(u32_le(write_u32_le(0xdead_beef)), 0xdead_beef);
        assert_eq!(
            u64_be(write_u64_be(0x0123_4567_89ab_cdef)),
            0x0123_4567_89ab_cdef
        );
        assert_eq!(
            u64_le(write_u64_le(0x0123_4567_89ab_cdef)),
            0x0123_4567_89ab_cdef
        );
        assert_eq!(u16_be(write_u16_be(0xABCD)), 0xABCD);
        assert_eq!(i64_be(write_i64_be(-2)), -2);
        assert_eq!(write_u32_be(0xdead_beef), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(write_u32_le(0xdead_beef), [0xef, 0xbe, 0xad, 0xde]);
    }

    #[test]
    fn cursor_reads_advance_and_report_absolute_offsets() {
        let buf = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut c = Cursor::new(&buf, 0x1000);
        assert_eq!(c.offset(), 0x1000);
        assert_eq!(c.u8().unwrap(), 0x00);
        assert_eq!(c.offset(), 0x1001);
        assert_eq!(c.u16_be().unwrap(), 0x0102);
        assert_eq!(c.take(2).unwrap(), &[0x03, 0x04]);
        assert_eq!(c.remaining(), 1);
        assert_eq!(c.rest(), &[0x05]);
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn cursor_short_read_is_truncated_at_the_field_offset() {
        let buf = [0xAA, 0xBB];
        let mut c = Cursor::new(&buf, 0x40);
        assert_eq!(c.u8().unwrap(), 0xAA);
        // One byte left, ask for a u32: truncation reported at the field's absolute offset (0x41),
        // short by 3.
        match c.u32_be() {
            Err(Error::Truncated { offset, needed }) => {
                assert_eq!(offset, 0x41);
                assert_eq!(needed, 3);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn cursor_skip_past_end_is_truncated() {
        let buf = [0u8; 4];
        let mut c = Cursor::new(&buf, 0);
        assert!(c.skip(5).is_err());
        assert!(c.skip(4).is_ok());
        assert_eq!(c.remaining(), 0);
    }
}
