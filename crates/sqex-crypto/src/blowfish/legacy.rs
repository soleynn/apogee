//! The SE launcher Blowfish variant.
//!
//! Its key schedule folds each key byte in as **signed**, so any key byte >= 0x80 sign-extends into
//! the high bits and the result diverges from textbook Blowfish. This is reproduced deliberately
//! (SE ships it, so byte-identity requires it) and pinned by the high-byte golden. The
//! launch-argument key is ASCII hex (all bytes < 0x80), so the divergence is dormant there but is
//! tested explicitly so it can never drift unnoticed. Blocks are little-endian.

use super::{BlowfishCore, Endian};

/// Zero-padded ECB Blowfish with the signed-byte key schedule and little-endian blocks.
pub struct LegacyBlowfish {
    core: BlowfishCore,
}

impl LegacyBlowfish {
    /// Run the key schedule over `key`.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self {
            core: BlowfishCore::new(key, true),
        }
    }

    /// Encrypt `data`, zero-padded to an 8-byte multiple.
    #[must_use]
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.core.encrypt_ecb(data, Endian::Little)
    }

    /// Decrypt `data` (a multiple of 8 bytes).
    #[must_use]
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.core.decrypt_ecb(data, Endian::Little)
    }

    #[cfg(test)]
    pub(crate) fn state_dump(&self) -> String {
        self.core.state_dump()
    }
}
