//! Textbook Blowfish: unsigned key schedule, big-endian blocks, zero-padded ECB. Built now for the
//! ticket path; it matches published Blowfish test vectors.

use super::{BlowfishCore, Endian};

/// Zero-padded ECB Blowfish in canonical (big-endian) block order.
pub struct Blowfish {
    core: BlowfishCore,
}

impl Blowfish {
    /// Run the key schedule over `key`.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self {
            core: BlowfishCore::new(key, false),
        }
    }

    /// Encrypt `data`, zero-padded to an 8-byte multiple.
    #[must_use]
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.core.encrypt_ecb(data, Endian::Big)
    }

    /// Decrypt `data` (a multiple of 8 bytes).
    #[must_use]
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.core.decrypt_ecb(data, Endian::Big)
    }

    #[cfg(test)]
    pub(crate) fn state_dump(&self) -> String {
        self.core.state_dump()
    }
}
