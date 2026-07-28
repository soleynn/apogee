//! The one endianness home. Every `from_*_bytes` in the crate lives here, behind named little-endian
//! helpers, so a field can't be read in the wrong order by accident: SqPack containers are entirely
//! game-native little-endian (the opposite default from ZiPatch chunk framing).

use crate::error::{Error, Result};

/// Read a `u32` from four little-endian bytes.
#[must_use]
pub fn u32_le(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

/// Read a `u16` from two little-endian bytes (a dat entry's block sizes).
#[must_use]
pub fn u16_le(bytes: [u8; 2]) -> u16 {
    u16::from_le_bytes(bytes)
}

/// Read a `u64` from eight little-endian bytes (an index1 entry's folder/file hash pair).
#[must_use]
pub fn u64_le(bytes: [u8; 8]) -> u64 {
    u64::from_le_bytes(bytes)
}

/// Read a `u32` from `buf` at `off`, little-endian. The caller guarantees `buf.len() >= off + 4`.
#[must_use]
pub fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32_le([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Write a `u32` as four little-endian bytes. The crate reads archives and never writes them; what
/// needs this is the header a model extraction has to put back (the packer folds it into the entry
/// header), plus the container fixtures the tests build.
#[must_use]
pub fn write_u32_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Write a `u16` as two little-endian bytes, for the same reason as [`write_u32_le`].
#[must_use]
pub fn write_u16_le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

/// Write a `u64` as eight little-endian bytes. Test-only, for the same reason as [`write_u32_le`].
#[cfg(test)]
#[must_use]
pub fn write_u64_le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

/// A forward-only reader over a container's bytes. It never allocates and never reads past the end:
/// a short read is an [`Error::Truncated`] whose `offset` is the absolute file position of the field,
/// not a slice-relative one, so the taxonomy's triage promise holds.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Absolute file offset of `buf[0]`, so reported offsets point into the real file.
    base: u64,
}

impl<'a> Cursor<'a> {
    /// A cursor over `buf`, whose byte 0 sits at absolute file offset `base`.
    #[must_use]
    pub fn new(buf: &'a [u8], base: u64) -> Self {
        Self { buf, pos: 0, base }
    }

    /// The absolute file offset of the next unread byte. Saturating, because the base is a
    /// caller-supplied file position at the public parse entry points and only ever reported.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.base.saturating_add(self.pos as u64)
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
        let out =
            <[u8; N]>::try_from(&self.buf[start..start + N]).map_err(|_| Error::IndexCorrupt {
                offset: self.offset(),
                detail: "array conversion",
            })?;
        self.pos += N;
        Ok(out)
    }

    /// Read a single byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    /// Read a little-endian `u16`.
    pub fn u16_le(&mut self) -> Result<u16> {
        Ok(u16_le(self.array()?))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_order() {
        assert_eq!(u32_le([0x11, 0x22, 0x33, 0x44]), 0x4433_2211);
        assert_eq!(
            u64_le([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
            0x8877_6655_4433_2211
        );
    }

    #[test]
    fn read_at_offset_slices_the_right_window() {
        let buf = [0xde, 0xad, 0x11, 0x22, 0x33, 0x44, 0xbe, 0xef];
        assert_eq!(read_u32_le(&buf, 2), 0x4433_2211);
    }

    #[test]
    fn writer_inverts_reader() {
        assert_eq!(write_u32_le(0x4433_2211), [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(u32_le(write_u32_le(0xdead_beef)), 0xdead_beef);
        assert_eq!(
            u64_le(write_u64_le(0xdead_beef_feed_face)),
            0xdead_beef_feed_face
        );
    }

    #[test]
    fn cursor_reads_fields_in_order() {
        let buf = [0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0x01, 0x02, 0x03, 0x04];
        let mut c = Cursor::new(&buf, 0x400);
        assert_eq!(c.u32_le().unwrap(), 0x4433_2211);
        c.skip(2).unwrap();
        assert_eq!(c.take(4).unwrap(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(c.remaining(), 0);
        assert_eq!(c.offset(), 0x40A);
    }

    #[test]
    fn cursor_short_read_is_truncated_at_the_absolute_field_offset() {
        // The cursor's base is the field's real file position, so triage points into the file rather
        // than into whatever slice the parser happened to hold.
        let buf = [0u8; 5];
        let mut c = Cursor::new(&buf, 0x800);
        c.skip(3).unwrap();
        match c.u32_le() {
            Err(Error::Truncated { offset, needed }) => {
                assert_eq!(offset, 0x803);
                assert_eq!(needed, 2);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }
}
