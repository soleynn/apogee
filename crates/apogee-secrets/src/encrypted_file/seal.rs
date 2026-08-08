//! The two envelopes the file is closed with, and where their nonces come from.
//!
//! One key seals both. The **check** envelope has no plaintext at all and exists only so that a key
//! can be tested against a file: it opens when the passphrase and the work parameters are the ones
//! the file was sealed under, and fails otherwise. The **body** envelope carries the record table and
//! is bound to the header fields that decide the key plus its own nonce, so it cannot be spliced onto
//! a header sealed under other parameters.
//!
//! What the split buys is the one distinction a front end cannot afford to get wrong: a mistyped
//! passphrase and a damaged file look identical to a single tag, and offering "start over" for a typo
//! destroys the secrets.
//!
//! The reading is not "check fails means the key is wrong", which was too strong: an edited check
//! nonce or check tag fails the check under a perfectly good key, and a tag cannot tell a wrong key
//! from a wrong nonce. Those two fields are the one region the body is deliberately *not* bound to,
//! so the body settles it. Check passes and body fails is a damaged file. Check fails and body opens
//! is a damaged check envelope, also a damaged file. Only when both fail is the key wrong.

use chacha20poly1305::aead::{AeadInOut, KeyInit, inout::InOutBuf};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};

use super::frame::{KEY_LEN, NONCE_LEN, TAG_LEN, corrupt};
use crate::SecretsError;

/// Draw bytes from the operating system generator.
///
/// A failure is reported and nothing is written. There is no fallback to a weaker source and no zero
/// default: a store sealed under a predictable nonce is a store with no seal, and it would look
/// exactly like a working one.
///
/// The buffer is never given a value of its own on the way. Filling a zeroed array would produce the
/// same bytes, and it would also mean a salt or a nonce briefly holds a constant, which is a thing to
/// be one edit away from rather than to write on purpose. Nothing here is `unsafe`: the generator
/// hands back the initialized slice, and the length is checked rather than assumed.
pub(crate) fn draw<const N: usize>() -> Result<[u8; N], SecretsError> {
    let failed = || SecretsError::Backend {
        step: "draw random bytes",
    };
    let mut out = [std::mem::MaybeUninit::<u8>::uninit(); N];
    let filled = getrandom::fill_uninit(&mut out).map_err(|_| failed())?;
    <[u8; N]>::try_from(&*filled).map_err(|_| failed())
}

/// Close the check envelope over `aad`, producing the tag the file carries.
pub(crate) fn seal_check(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
) -> Result<[u8; TAG_LEN], SecretsError> {
    let mut empty: [u8; 0] = [];
    cipher(key)
        .encrypt_inout_detached(&XNonce::from(*nonce), aad, InOutBuf::from(&mut empty[..]))
        .map(Into::into)
        .map_err(|_| SecretsError::Backend { step: "seal" })
}

/// Answer whether `key` is the key this file was sealed under.
///
/// # Errors
/// [`SecretsError::WrongPassphrase`], which is also what an edited salt or an edited work parameter
/// produces: a key derived from edited parameters is a wrong key, and no check can tell the two
/// apart. It is *not* the last word on the passphrase, though, because an edited nonce or tag
/// produces it too. The caller resolves that against the body envelope, which those two fields are
/// left out of.
pub(crate) fn open_check(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), SecretsError> {
    let mut empty: [u8; 0] = [];
    cipher(key)
        .decrypt_inout_detached(
            &XNonce::from(*nonce),
            aad,
            InOutBuf::from(&mut empty[..]),
            &Tag::from(*tag),
        )
        .map_err(|_| SecretsError::WrongPassphrase)
}

/// Encrypt `buf` in place and hand back its tag.
pub(crate) fn seal_body(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], SecretsError> {
    cipher(key)
        .encrypt_inout_detached(&XNonce::from(*nonce), aad, InOutBuf::from(buf))
        .map(Into::into)
        .map_err(|_| SecretsError::Backend { step: "seal" })
}

/// Decrypt `buf` in place, having checked its tag first.
///
/// # Errors
/// [`SecretsError::Corrupt`]. Only reached once the check envelope has already proved the key, so a
/// failure here is damage to the file rather than a wrong passphrase.
pub(crate) fn open_body(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), SecretsError> {
    cipher(key)
        .decrypt_inout_detached(
            &XNonce::from(*nonce),
            aad,
            InOutBuf::from(buf),
            &Tag::from(*tag),
        )
        .map_err(|_| corrupt("authentication tag"))
}

/// Build the cipher for one operation.
///
/// Built per call from the cached key rather than held, so the erasure guarantee is this crate's and
/// does not rest on a dependency feature staying enabled. A key schedule is microseconds against a
/// derivation measured in tens of them.
fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&Key::from(*key))
}

// A sibling file rather than an inline module, unlike the rest of this crate. These tests need
// fixed salts, nonces and keys, which is what a known-answer vector is, and the security scan reads
// a literal in that position as a hard-coded credential. Its configuration already excludes test
// files by name, so the tests move to where the exclusion can see them rather than the rule being
// turned off for code where it would be right.
#[cfg(test)]
mod tests;
