//! The marker a patcher leaves over a stretch of a dat file it wiped.
//!
//! When a patch deletes or moves a file the space its slot held is not reclaimed: the run is zeroed
//! and a 24-byte header is stamped at its front saying how many 128-byte blocks the run covers. Runs
//! chain, so a stretch no entry claims is one such header after another, each spanning what it
//! declares, and reading them is the only way to tell space a patcher accounted for from space
//! something scribbled on.
//!
//! The write side lives here beside the read side on purpose: the two cannot be pinned against each
//! other, nor against the reference patcher, if either owns its own copy of the layout.

use crate::bytes;

use super::DATA_UNIT;

/// The byte length of the empty-block header a patcher stamps at the front of a region it wipes.
pub const EMPTY_BLOCK_HEADER_LEN: usize = 24;

/// Where the header declares how many blocks its region spans.
const BLOCK_COUNT_AT: usize = 12;

/// The header a patcher stamps at the front of a wiped region: the block size (always
/// [`DATA_UNIT`]), a zero, a zero decoded size, the block count less one as a `u64`, then a zero.
///
/// The count field is eight bytes, not four: a `block_count` of 0 wraps to `0xFFFF_FFFF_FFFF_FFFF`,
/// so its high half is meaningful. This is the write side of what [`empty_block_count`] recognises.
#[must_use]
pub fn empty_block_header(block_count: u32) -> [u8; EMPTY_BLOCK_HEADER_LEN] {
    let mut out = [0u8; EMPTY_BLOCK_HEADER_LEN];
    out[0..4].copy_from_slice(&bytes::write_u32_le(DATA_UNIT));
    // The word at 4 and the decoded size at 8 stay zero, as does the trailing word at 20.
    out[BLOCK_COUNT_AT..BLOCK_COUNT_AT + 8]
        .copy_from_slice(&bytes::write_u64_le(u64::from(block_count).wrapping_sub(1)));
    out
}

/// How many [`DATA_UNIT`]-byte blocks the header at the front of `head` claims, or `None` when those
/// bytes are not one of these headers or claim a count no region can have.
///
/// Never `Some(0)`: the stored field is the count less one, so a region is at least one block, which
/// is what keeps a chain walk advancing. The one field value that would spell zero blocks
/// (`0xFFFF_FFFF_FFFF_FFFF`, which is how a `block_count` of 0 is written) is `None` for that reason.
#[must_use]
pub fn empty_block_count(head: &[u8]) -> Option<u64> {
    let head = head.get(..EMPTY_BLOCK_HEADER_LEN)?;
    let word = |at: usize| bytes::read_u32_le(head, at);
    if word(0) != DATA_UNIT || word(4) != 0 || word(8) != 0 || word(20) != 0 {
        return None;
    }
    let stored =
        bytes::u64_le(<[u8; 8]>::try_from(head.get(BLOCK_COUNT_AT..BLOCK_COUNT_AT + 8)?).ok()?);
    stored.checked_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_is_twenty_four_little_endian_bytes() {
        // Pinned byte for byte, because this is what the reader recognises and what the patcher
        // writes: a disagreement between the two would make every wiped region of an install
        // unaccountable.
        assert_eq!(
            empty_block_header(2),
            [
                0x80, 0x00, 0x00, 0x00, // block size = 128
                0x00, 0x00, 0x00, 0x00, // 0
                0x00, 0x00, 0x00, 0x00, // decoded size = 0
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // block count - 1, as a u64
                0x00, 0x00, 0x00, 0x00, // 0
            ]
        );
        assert_eq!(&empty_block_header(1)[12..20], &[0; 8]);
        // A count of 0 is the one value whose bytes tell the true 24-byte header from a mistaken
        // 20-byte one, since the wrap fills the field's high half.
        assert_eq!(&empty_block_header(0)[12..20], &[0xFF; 8]);
    }

    #[test]
    fn a_header_reads_back_the_count_it_was_written_with() {
        for count in [1u32, 2, 7, 0x1_0000, u32::MAX] {
            assert_eq!(
                empty_block_count(&empty_block_header(count)),
                Some(u64::from(count))
            );
        }
        // The one count that cannot be read back: its field is all ones, which spells no region at
        // all, and a walk that took it as zero blocks would never advance.
        assert_eq!(empty_block_count(&empty_block_header(0)), None);
    }

    #[test]
    fn bytes_that_are_not_one_of_these_headers_claim_nothing() {
        let good = empty_block_header(3);
        assert_eq!(empty_block_count(&good), Some(3));
        // Every word the header fixes is checked, so an entry header or a codec block sitting where a
        // wiped region should be is not mistaken for one.
        for (at, byte) in [(0usize, 0x10u8), (4, 1), (8, 1), (20, 1)] {
            let mut bad = good;
            bad[at] = byte;
            assert_eq!(empty_block_count(&bad), None, "byte {at}");
        }
        // Fewer bytes than the header needs claims nothing rather than reading what follows.
        assert_eq!(empty_block_count(&good[..EMPTY_BLOCK_HEADER_LEN - 1]), None);
        assert_eq!(empty_block_count(&[]), None);
    }
}
