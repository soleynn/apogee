//! The write-side SqPack shim: byte layouts the apply engine stamps into `.dat` files that are not
//! the shared block codec's job. Today that is the empty-block header a `D` (DeleteData) or
//! `E` (ExpandData) command writes at the start of the region it wipes.
//!
//! The layout itself lives in `apogee-sqpack` beside the reader that recognises it, for the reason
//! the block codec does: a region this crate stamps is a region that crate has to account for, and
//! two copies of one layout can disagree. What stays here is the apply engine's name for it and the
//! byte pin below, which is this crate's own check that what it writes is what the reference patcher
//! writes.

/// The fixed byte length of the empty-block header a `D`/`E` command stamps.
pub(crate) const EMPTY_BLOCK_HEADER_LEN: usize = apogee_sqpack::EMPTY_BLOCK_HEADER_LEN;

/// The empty-block header written at the start of the region a `D`/`E` command wipes.
///
/// The wiped region is zeroed separately; this header overwrites its first
/// [`EMPTY_BLOCK_HEADER_LEN`] bytes.
pub(crate) fn empty_block_header(block_count: u32) -> [u8; EMPTY_BLOCK_HEADER_LEN] {
    apogee_sqpack::empty_block_header(block_count)
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
