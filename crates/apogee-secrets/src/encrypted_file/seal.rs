//! The two envelopes the file is closed with, and where their nonces come from.
//!
//! One key seals both. The **check** envelope has no plaintext at all and exists only so that a key
//! can be tested against a file: it opens when the passphrase and the work parameters are the ones
//! the file was sealed under, and fails otherwise. The **body** envelope carries the record table and
//! is bound to the whole header, so nothing in the file can be moved, swapped, or spliced without it
//! failing.
//!
//! What the split buys is the one distinction a front end cannot afford to get wrong: a mistyped
//! passphrase and a damaged file look identical to a single tag, and offering "start over" for a typo
//! destroys the secrets. Check fails means the key is wrong. Check passes and body fails means the
//! key is right and the file is not.

use chacha20poly1305::aead::{AeadInOut, KeyInit, inout::InOutBuf};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};

use super::frame::{KEY_LEN, NONCE_LEN, TAG_LEN, corrupt};
use crate::SecretsError;

/// Draw bytes from the operating system generator.
///
/// A failure is reported and nothing is written. There is no fallback to a weaker source and no zero
/// default: a store sealed under a predictable nonce is a store with no seal, and it would look
/// exactly like a working one.
pub(crate) fn draw<const N: usize>() -> Result<[u8; N], SecretsError> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| SecretsError::Backend {
        step: "draw random bytes",
    })?;
    Ok(out)
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
/// apart.
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x5a; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x17; NONCE_LEN];

    #[test]
    fn a_body_round_trips_under_its_own_associated_data() {
        let mut buf = *b"the record table";
        let tag = seal_body(&KEY, &NONCE, b"header", &mut buf).expect("seal");
        assert_ne!(&buf, b"the record table");
        open_body(&KEY, &NONCE, b"header", &mut buf, &tag).expect("open");
        assert_eq!(&buf, b"the record table");
    }

    /// The body is bound to the whole header, which is what stops one file's body being spliced onto
    /// another's header. Without the binding, two stores under one passphrase would be swappable.
    #[test]
    fn a_body_sealed_under_one_header_will_not_open_under_another() {
        let mut buf = *b"the record table";
        let tag = seal_body(&KEY, &NONCE, b"header one", &mut buf).expect("seal");
        let err = open_body(&KEY, &NONCE, b"header two", &mut buf, &tag);
        assert!(matches!(
            err,
            Err(SecretsError::Corrupt {
                detail: "authentication tag"
            })
        ));
    }

    /// The check envelope is the only thing separating a typo from a damaged file, so its two
    /// answers are pinned here rather than left to whichever error the cipher happens to return.
    #[test]
    fn the_check_envelope_answers_whether_the_key_is_the_right_one() {
        let tag = seal_check(&KEY, &NONCE, b"parameters").expect("seal");
        open_check(&KEY, &NONCE, b"parameters", &tag).expect("the right key");

        let mut wrong = KEY;
        wrong[0] ^= 1;
        assert!(matches!(
            open_check(&wrong, &NONCE, b"parameters", &tag),
            Err(SecretsError::WrongPassphrase)
        ));
        assert!(matches!(
            open_check(&KEY, &NONCE, b"other parameters", &tag),
            Err(SecretsError::WrongPassphrase)
        ));
    }

    /// Every write draws its own nonces. A repeat under one key is the failure mode this cipher has
    /// no defence against, so the property is asserted rather than assumed from the call site.
    #[test]
    fn drawn_bytes_are_not_the_same_twice() {
        let first: [u8; NONCE_LEN] = draw().expect("draw");
        let second: [u8; NONCE_LEN] = draw().expect("draw");
        assert_ne!(first, second);
        assert_ne!(first, [0u8; NONCE_LEN]);
    }
}
