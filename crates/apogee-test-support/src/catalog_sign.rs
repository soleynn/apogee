//! Test-only Ed25519 keypair for signing synthetic runner/component manifests.
//!
//! TEST-ONLY KEYPAIR — never a production key. The seed is a fixed, published constant so unit and
//! integration tests across crates share one verifying key; nothing here is secret.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// The fixed 32-byte seed the test signing key derives from. Deliberately trivial (`0..32`) so it is
/// unmistakably a test value, never mistaken for a real key.
const TEST_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// The deterministic test signing key.
#[must_use]
pub fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_SEED)
}

/// The verifying (public) key that manifest-verification tests check signatures against.
#[must_use]
pub fn test_verifying_key() -> VerifyingKey {
    test_signing_key().verifying_key()
}

/// The raw 32 public-key bytes (e.g. to stand in for a compiled-in key in a test).
#[must_use]
pub fn test_verifying_key_bytes() -> [u8; 32] {
    test_verifying_key().to_bytes()
}

/// Sign `manifest` with the test key, returning the 64-byte detached signature.
#[must_use]
pub fn sign_manifest(manifest: &[u8]) -> [u8; 64] {
    test_signing_key().sign(manifest).to_bytes()
}
