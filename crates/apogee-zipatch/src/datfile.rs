//! The private write-side SqPack shim: byte layouts the apply engine stamps into `.dat` files that
//! are not the shared block codec's job. Today that is the empty-block header a `D` (DeleteData) or
//! `E` (ExpandData) command writes at the start of the region it wipes.
//!
//! These bytes are game-native little-endian and must match the reference patcher exactly, so they
//! are built through the crate's one endianness home ([`crate::bytes`]).

use crate::bytes;

/// The fixed byte length of the empty-block header a `D`/`E` command stamps.
pub(crate) const EMPTY_BLOCK_HEADER_LEN: usize = 24;

/// The empty-block header written at the start of the region a `D`/`E` command wipes. Five
/// little-endian fields: block size (always 128), a zero, a zero file size, the block count minus one
/// as a **u64**, then a trailing zero, for twenty-four bytes total.
///
/// The count-minus-one field is eight bytes, not four: the reference stamps it from a 64-bit
/// subtraction, so a `block_count` of 0 wraps to `0xFFFF_FFFF_FFFF_FFFF` and the field's high four
/// bytes are meaningful. Writing four bytes here would drift from the reference on that edge.
///
/// The wiped region is zeroed separately; this header overwrites its first [`EMPTY_BLOCK_HEADER_LEN`]
/// bytes.
pub(crate) fn empty_block_header(block_count: u32) -> [u8; EMPTY_BLOCK_HEADER_LEN] {
    let mut out = [0u8; EMPTY_BLOCK_HEADER_LEN];
    out[0..4].copy_from_slice(&bytes::write_u32_le(128)); // block size, always 128
    // out[4..8] (a zero) and out[8..12] (the zero file size) stay zero.
    out[12..20].copy_from_slice(&bytes::write_u64_le(u64::from(block_count).wrapping_sub(1)));
    // out[20..24] (the trailing field) stays zero.
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_block_header_is_twenty_four_little_endian_bytes() {
        // block_count 2: the count-minus-one field is (2 - 1) = 1, so byte[12] = 1, the rest zero.
        assert_eq!(
            empty_block_header(2),
            [
                0x80, 0x00, 0x00, 0x00, // block size = 128
                0x00, 0x00, 0x00, 0x00, // 0
                0x00, 0x00, 0x00, 0x00, // file size = 0
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, // block_count - 1 = 1 (u64 LE)
                0x00, 0x00, 0x00, 0x00, // 0
            ]
        );
        // block_count 1: the field is 0.
        assert_eq!(&empty_block_header(1)[12..20], &[0, 0, 0, 0, 0, 0, 0, 0]);
        // block_count 0: 0 - 1 wraps in 64-bit to all ones. This is the only value whose bytes
        // distinguish the true 24-byte header from a mistaken 20-byte one, so it is pinned here.
        assert_eq!(
            &empty_block_header(0)[12..20],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }
}
