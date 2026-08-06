//! Where the fallback store gets the passphrase it cannot ask for itself.

use crate::{Secret, SecretsError};

/// The source an [`EncryptedFile`](crate::EncryptedFile) asks when it needs to unlock.
///
/// This library never prompts. Prompting is presentation, and a library that opened a terminal or a
/// dialog would be deciding how the launcher looks from underneath the layer that owns that decision.
/// This is the seam whichever front end does the asking plugs into.
///
/// It is asked at the moment a secret is wanted rather than when the store is constructed, so a
/// command that never touches a secret never makes the user type anything. It is asked once per
/// stretch of use per set of stored parameters: the derived key is kept until it has gone unused for
/// [`EncryptedFile::DEFAULT_IDLE`](crate::EncryptedFile::DEFAULT_IDLE), the passphrase is dropped
/// inside the call that used it, and a failed attempt is not remembered, which is how a mistyped one
/// is corrected by simply trying again. A source that prompts is asked again by a launcher that has
/// been left alone, and should not treat the second prompt as a fault.
///
/// An implementation must be callable from any thread and must not cache what it returns. It must
/// also not call back into the store that asked it: the store holds its lock across the whole
/// operation, so a re-entrant source deadlocks.
///
/// **A write holds the cross-process lock while this is answered**, which for a terminal prompt is
/// milliseconds and for a modal dialog is however long the user takes to notice it. A second
/// launcher process writing at that moment waits. The alternative is to unlock, prompt, and take the
/// lock again, and that is worse: the file could be re-sealed in the gap, so the write would have to
/// re-read and redo its work anyway, and the second process's write would be the one at risk. A front
/// end that prompts modally should ask before it starts a write, not during one.
pub trait Passphrase: Send + Sync {
    /// Produce the passphrase.
    ///
    /// # Errors
    /// [`SecretsError::Locked`] when there is none to give, which covers a user who dismissed the
    /// prompt and one who typed nothing. That variant is exactly "an unlock that was not completed",
    /// and a caller answers it by trying again rather than by going to fix something.
    fn unlock(&self) -> Result<Secret, SecretsError>;

    /// Whether this source can produce a passphrase at all.
    ///
    /// Read by [`SecretStore::probe`](crate::SecretStore::probe), which must never ask. A source with
    /// nothing to give makes the store report itself unusable, so nothing offers to save a password
    /// into a store that is going to refuse it.
    fn can_prompt(&self) -> bool {
        true
    }
}

/// The [`Passphrase`] source with nothing to give.
///
/// What a store gets when the front end holding it cannot ask: a headless run, a service, or a shell
/// that has not wired a prompt yet. Every call is refused and the store reports itself unusable,
/// rather than a secret being written somewhere the user did not choose.
#[derive(Debug, Default)]
pub struct Unprompted;

impl Unprompted {
    /// Construct the source that never answers.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Passphrase for Unprompted {
    fn unlock(&self) -> Result<Secret, SecretsError> {
        Err(SecretsError::Locked)
    }

    fn can_prompt(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both halves matter and they are answered by different code. A source that refused to unlock
    /// while claiming it could prompt would have the store advertise itself as usable and then fail
    /// every write.
    #[test]
    fn the_source_with_nothing_to_give_says_so_and_refuses() {
        assert!(matches!(
            Unprompted::new().unlock(),
            Err(SecretsError::Locked)
        ));
        assert!(!Unprompted.can_prompt());
    }

    /// The default is the answer for every source that does prompt, so it has to be the permissive
    /// one: an implementation that only wrote `unlock` must not have its store reported unusable.
    #[test]
    fn a_source_that_only_implements_unlock_can_prompt() {
        struct Typed;
        impl Passphrase for Typed {
            fn unlock(&self) -> Result<Secret, SecretsError> {
                Ok(Secret::new(b"pw".to_vec()))
            }
        }
        assert!(Typed.can_prompt());
    }
}
