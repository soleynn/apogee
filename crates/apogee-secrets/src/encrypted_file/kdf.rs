//! Turning a passphrase into the key the store is sealed under.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use super::frame::{KEY_LEN, SALT_LEN};
use crate::SecretsError;

/// The least work a file this build will open was sealed under.
///
/// The published minimum for password storage, and the floor a hostile header is measured against.
/// It is also what the test suite writes, so no test hook lowers a production constant to run fast.
const MIN_MEMORY_KIB: u32 = 19_456;

/// The most memory a derivation may ask for. This is what bounds the allocation the derivation makes,
/// so it is checked when the parameters are parsed and never at the point of allocation.
const MAX_MEMORY_KIB: u32 = 1 << 20;

const MIN_PASSES: u32 = 2;
const MAX_PASSES: u32 = 16;
const MIN_LANES: u32 = 1;
const MAX_LANES: u32 = 4;

// The algorithm's own constraint on the pair, so the floor cannot be lowered into a band where a
// legal lane count is rejected by the library rather than by the check above.
const _: () = assert!(MIN_MEMORY_KIB >= 8 * MAX_LANES);

/// The work an Argon2id derivation is asked for.
///
/// Carried in the file rather than compiled into the reader: a store opens forever at the cost it was
/// sealed under, and raising what new stores cost is a one-constant edit that orphans nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

impl KdfCost {
    /// The cost a store created by this build is sealed under.
    ///
    /// Measured, not picked. From the `kdf_cost` example on an eight-core Zen 2 desktop, release
    /// build, median of three, one lane throughout, as millisecond and peak resident mebibyte pairs:
    /// 19456 KiB over 2 passes is 16 and 21, 32768 over 3 is 43 and 53, 65536 over 3 is 92 and 85,
    /// 98304 over 3 is 151 and 117, 131072 over 3 is 200 and 148, 262144 over 3 is 423 and 276.
    ///
    /// Lanes stay at one because this build derives them sequentially: 65536 over 3 measured 95 ms at
    /// four lanes against 92 at one, so a second lane costs the same wall clock here while handing an
    /// attacker parallelism and cutting the memory each lane has to hold.
    ///
    /// 64 MiB over 3 passes is the second profile in the Argon2 recommendations with the lane count
    /// cut for that reason. The first profile's 2 GiB is a rude allocation in a launcher sharing
    /// memory with a GPU, and the peak figures above are why: a cell that lands in swap on a handheld
    /// costs seconds rather than the milliseconds it measured.
    ///
    /// Still owed: the same sweep on handheld hardware, idle and with a game resident, which is the
    /// case that decides this rather than a desktop's. The cost travels in each file, so lowering
    /// this later is one edit and every store already written keeps opening at what it was sealed
    /// under.
    pub const CURRENT: Self = Self {
        memory_kib: 65_536,
        passes: 3,
        lanes: 1,
    };

    /// Parameters inside the band this build accepts, or `None`.
    ///
    /// The band is what a header read off disk is measured against, so this is the check that stops
    /// a hostile file making an honest process allocate for it or spin on it.
    #[must_use]
    pub const fn new(memory_kib: u32, passes: u32, lanes: u32) -> Option<Self> {
        if memory_kib < MIN_MEMORY_KIB
            || memory_kib > MAX_MEMORY_KIB
            || passes < MIN_PASSES
            || passes > MAX_PASSES
            || lanes < MIN_LANES
            || lanes > MAX_LANES
        {
            return None;
        }
        Some(Self {
            memory_kib,
            passes,
            lanes,
        })
    }

    /// The least work this build will accept, which is the published minimum for password storage.
    ///
    /// What a test seals with, so the suite exercises the real floor rather than a value only tests
    /// can reach.
    #[must_use]
    pub const fn floor() -> Self {
        Self {
            memory_kib: MIN_MEMORY_KIB,
            passes: MIN_PASSES,
            lanes: MIN_LANES,
        }
    }

    /// Memory, in kibibytes.
    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// Passes over that memory.
    #[must_use]
    pub const fn passes(self) -> u32 {
        self.passes
    }

    /// Lanes. Derived sequentially here, so raising this buys no wall clock and costs work.
    #[must_use]
    pub const fn lanes(self) -> u32 {
        self.lanes
    }
}

impl Default for KdfCost {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Derive the sealing key from `passphrase` and `salt` at `cost`.
///
/// The working memory is allocated here, after the band check, and erased when it drops. What cannot
/// be erased, recorded rather than glossed: the library copies the passphrase into a hash state
/// during its first block and does not clear that state, so a copy of the passphrase outlives this
/// call inside the dependency. Closing that needs a fork of it.
pub(crate) fn derive(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    cost: KdfCost,
) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretsError> {
    let step = "derive a key";
    let params = Params::new(
        cost.memory_kib(),
        cost.passes(),
        cost.lanes(),
        Some(KEY_LEN),
    )
    .map_err(|_| SecretsError::Backend { step })?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // The block count comes from parameters that were band-checked before this function was reached,
    // so the reservation is bounded by `MAX_MEMORY_KIB` and not by a number read off disk.
    let mut blocks = Zeroizing::new(vec![Block::default(); argon.params().block_count()]);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    // The library's error is matched and dropped like every other dependency error in this crate:
    // it renders its own parameters, and this enum is wrapped by the launcher's top-level error.
    argon
        .hash_password_into_with_memory(passphrase, salt, &mut *key, blocks.as_mut_slice())
        .map_err(|_| SecretsError::Backend { step })?;
    Ok(key)
}

// A sibling file rather than an inline module, unlike the rest of this crate. These tests need
// fixed salts, nonces and keys, which is what a known-answer vector is, and the security scan reads
// a literal in that position as a hard-coded credential. Its configuration already excludes test
// files by name, so the tests move to where the exclusion can see them rather than the rule being
// turned off for code where it would be right.
#[cfg(test)]
mod tests;
