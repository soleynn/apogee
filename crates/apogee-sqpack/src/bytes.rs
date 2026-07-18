//! The one endianness home. Every `from_*_bytes` in the crate lives here, behind named little-endian
//! helpers, so a field can't be read in the wrong order by accident: SqPack containers are entirely
//! game-native little-endian (the opposite default from ZiPatch chunk framing).

/// Read a `u32` from four little-endian bytes.
#[must_use]
pub fn u32_le(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

/// Read a `u32` from `buf` at `off`, little-endian. The caller guarantees `buf.len() >= off + 4`.
#[must_use]
pub fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32_le([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Write a `u32` as four little-endian bytes. Only container and block *fixtures* need to write
/// (the codec is read-only), so this stays test-only while keeping their byte order defined here too.
#[cfg(test)]
#[must_use]
pub fn write_u32_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_order() {
        assert_eq!(u32_le([0x11, 0x22, 0x33, 0x44]), 0x4433_2211);
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
    }
}
