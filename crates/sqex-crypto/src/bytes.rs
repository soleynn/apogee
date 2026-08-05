//! The one endianness home. Every `from_*_bytes`/`to_*_bytes` in the crate lives here, behind named
//! little- and big-endian helpers, so a block can't be read in the wrong order by accident: the
//! launcher Blowfish variant is little-endian, the standard variant big-endian.
//!
//! Reading a block the wrong way round produces well-formed output that nothing here can tell from
//! the right answer, and only Square Enix rejects it. That is why the rule is mechanical rather than
//! a matter of care: `scripts/audit.sh` fails the build if a byte-order conversion appears anywhere
//! else in the crate.

/// Read a `u32` from four little-endian bytes.
#[must_use]
pub const fn u32_le(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

/// Read a `u32` from four big-endian bytes.
#[must_use]
pub const fn u32_be(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

/// Write a `u16` as two little-endian bytes.
#[must_use]
pub const fn write_u16_le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

/// Write a `u32` as four little-endian bytes.
#[must_use]
pub const fn write_u32_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Write a `u32` as four big-endian bytes.
#[must_use]
pub const fn write_u32_be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn little_and_big_endian_disagree_on_order() {
        let bytes = [0x11, 0x22, 0x33, 0x44];
        assert_eq!(u32_le(bytes), 0x4433_2211);
        assert_eq!(u32_be(bytes), 0x1122_3344);
    }

    #[test]
    fn writers_invert_readers() {
        let v = 0xdead_beef;
        assert_eq!(u32_le(write_u32_le(v)), v);
        assert_eq!(u32_be(write_u32_be(v)), v);
        assert_eq!(write_u32_le(v), [0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(write_u32_be(v), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(write_u16_le(0xbeef), [0xef, 0xbe]);
    }
}
