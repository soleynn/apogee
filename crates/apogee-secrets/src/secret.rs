//! The secret value and what it addresses.

use zeroize::Zeroizing;

/// A secret value, zeroized when it drops.
///
/// It deliberately implements no `Debug`, `Display`, `Clone`, `PartialEq`, `Default`, or
/// `serde::Serialize`. Printing one, comparing two, or serializing one into config is a compile
/// error rather than a review comment, and the compile-fail suite pins that.
///
/// Zeroization covers this buffer, including the capacity past its length. It cannot reach a copy
/// that existed before the bytes arrived here: a `String` that grew while it was being typed may
/// have left its earlier allocations on the heap, and only the buffer handed to [`Secret::new`] is
/// erased. Read a secret straight into one of these and drop it as soon as it has been used.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Wrap raw secret bytes. Takes the `Vec` by value, so no un-erased copy stays behind at the
    /// call site.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Wrap a secret held as text. `String::into_bytes` moves the heap buffer rather than copying
    /// it, so the text is not duplicated on the way in.
    #[must_use]
    pub fn from_string(text: String) -> Self {
        Self::new(text.into_bytes())
    }

    /// Borrow the raw bytes. Callers use them and drop them: they must not be logged, persisted, or
    /// copied into a longer-lived buffer.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// How many bytes the secret holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret holds no bytes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// No `impl Drop`: `Zeroizing` supplies one, and a manual `Drop` would additionally forbid moving the
// field out, which is not the invariant being protected here.

/// Which secret is addressed for an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretKind {
    /// The Square Enix account password.
    Password,
    /// The shared secret a one-time code is generated from.
    TotpSecret,
}

impl SecretKind {
    /// Every kind an account can have stored.
    ///
    /// The enum is `#[non_exhaustive]`, so a caller outside the crate cannot write this list itself.
    /// Anything that has to sweep an account reads it from here instead, and picks up a kind added
    /// later without being revisited: a hand-written list would go on compiling while it quietly
    /// stopped covering one.
    pub const ALL: [Self; 2] = [Self::Password, Self::TotpSecret];

    /// The kind's component of the stored key.
    ///
    /// This is on-disk contract: changing a slug orphans every secret already stored under the old
    /// one, with no error at the point of the change.
    pub(crate) const fn slug(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::TotpSecret => "totp",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A secret is moved into a command and then into a spawned task, so it has to stay `Send` and
    /// `'static`. It must not become `Clone`: a clone is a second buffer with its own lifetime.
    const _: fn() = || {
        fn assert_send_static<T: Send + 'static>() {}
        assert_send_static::<Secret>();
    };

    #[test]
    fn text_survives_the_round_trip() {
        let secret = Secret::from_string("correct horse".to_owned());
        assert_eq!(secret.expose(), b"correct horse");
        assert_eq!(secret.len(), 13);
        assert!(!secret.is_empty());
    }

    /// The buffer the secret holds is the caller's own, not a copy of it. A copy satisfies every
    /// assertion above while leaving the text where it was: what drops here is erased and what the
    /// caller handed over is not, so the value goes on sitting in freed heap for the allocator to
    /// hand out again. `String::into_bytes` gives back the same allocation, which is what makes the
    /// difference observable rather than merely asserted in a comment.
    #[test]
    fn text_moves_into_the_secret_rather_than_being_copied() {
        let text = "correct horse".to_owned();
        let held = text.as_ptr();

        let secret = Secret::from_string(text);

        assert_eq!(
            secret.expose().as_ptr(),
            held,
            "the text was copied into the secret and the original was left behind"
        );
    }

    #[test]
    fn an_empty_secret_reports_itself_empty() {
        let secret = Secret::new(Vec::new());
        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }

    /// `ALL` is what a sweep of an account iterates, so a kind missing from it is a secret left
    /// behind on a store the user asked to be emptied. The wildcard-free match is the enforcement:
    /// a new variant stops this compiling until it gains an arm, and the arm is next to the
    /// assertion that the list also has room for it.
    #[test]
    fn every_kind_is_swept() {
        #[allow(dead_code)]
        fn every_variant_has_an_entry(kind: SecretKind) {
            match kind {
                SecretKind::Password => (),
                SecretKind::TotpSecret => (),
            }
        }

        assert_eq!(
            SecretKind::ALL,
            [SecretKind::Password, SecretKind::TotpSecret]
        );
    }

    /// The slugs are half of the stored key, so they are frozen here rather than left to whatever
    /// the enum's variant names happen to be.
    #[test]
    fn kind_slugs_are_frozen() {
        assert_eq!(SecretKind::Password.slug(), "password");
        assert_eq!(SecretKind::TotpSecret.slug(), "totp");
    }
}
