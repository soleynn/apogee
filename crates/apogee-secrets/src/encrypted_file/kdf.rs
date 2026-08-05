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

#[cfg(test)]
mod tests {
    use super::*;

    /// If a dependency bump changes what the derivation produces, every stored secret is silently
    /// orphaned: the file still parses, the tags still fail, and the user is told their passphrase is
    /// wrong. Nothing else in the suite would catch it.
    #[test]
    fn the_derivation_is_pinned_to_a_known_answer() {
        let salt: [u8; SALT_LEN] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let key = derive(b"apogee test vector", &salt, KdfCost::floor()).expect("derive");
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "958659efad7bfa7268c148994dc27faa5079571d21fe10c1e59dd59d86d580e6"
        );
    }

    /// The floor is the whole defence for a store created on weak hardware, and the ceiling is what
    /// bounds the allocation. Both are read out of a file, so both are checked here rather than
    /// trusted.
    #[test]
    fn only_costs_inside_the_band_are_accepted() {
        assert!(KdfCost::new(MIN_MEMORY_KIB - 1, 2, 1).is_none());
        assert!(KdfCost::new(0, 2, 1).is_none());
        assert!(KdfCost::new(u32::MAX, 2, 1).is_none());
        assert!(KdfCost::new(MIN_MEMORY_KIB, 1, 1).is_none());
        assert!(KdfCost::new(MIN_MEMORY_KIB, u32::MAX, 1).is_none());
        assert!(KdfCost::new(MIN_MEMORY_KIB, 2, 0).is_none());
        assert!(KdfCost::new(MIN_MEMORY_KIB, 2, u32::MAX).is_none());
        assert_eq!(KdfCost::new(MIN_MEMORY_KIB, 2, 1), Some(KdfCost::floor()));
    }

    /// Lowering the shipped cost below the floor has to be one edit, not two that can be made apart.
    #[test]
    fn the_shipped_cost_is_inside_the_band() {
        assert_eq!(
            KdfCost::new(
                KdfCost::CURRENT.memory_kib(),
                KdfCost::CURRENT.passes(),
                KdfCost::CURRENT.lanes()
            ),
            Some(KdfCost::CURRENT)
        );
        assert_eq!(KdfCost::default(), KdfCost::CURRENT);
    }

    /// Every input has to reach the key. A parameter that was accepted, stored, and then ignored
    /// would let an attacker edit the header down to the floor and have the file still open.
    #[test]
    fn changing_any_one_input_changes_the_key() {
        let salt = [7u8; SALT_LEN];
        let base = derive(b"pw", &salt, KdfCost::floor()).expect("derive");
        let cases = [
            derive(b"px", &salt, KdfCost::floor()).expect("other passphrase"),
            derive(b"pw", &[8u8; SALT_LEN], KdfCost::floor()).expect("other salt"),
            derive(
                b"pw",
                &salt,
                KdfCost::new(MIN_MEMORY_KIB + 1024, 2, 1).expect("in band"),
            )
            .expect("other memory"),
            derive(
                b"pw",
                &salt,
                KdfCost::new(MIN_MEMORY_KIB, 3, 1).expect("in band"),
            )
            .expect("other passes"),
            derive(
                b"pw",
                &salt,
                KdfCost::new(MIN_MEMORY_KIB, 2, 2).expect("in band"),
            )
            .expect("other lanes"),
        ];
        for other in cases {
            assert_ne!(*base, *other);
        }
    }
}
