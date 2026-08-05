//! The storage seam and the handle the composition root holds.

use uuid::Uuid;

use crate::{BackendReport, OsKeyring, Secret, SecretKind, SecretsError};

/// Account-scoped secret storage.
///
/// Every method blocks and may raise the platform's unlock prompt, so a caller on an async runtime
/// must wrap the call in `tokio::task::spawn_blocking`.
pub trait SecretStore {
    /// Read a secret. A secret that was never stored is `Ok(None)`, not an error.
    ///
    /// # Errors
    /// [`SecretsError::Locked`] if the store is locked and was not unlocked,
    /// [`SecretsError::NoBackend`] if no store answered, [`SecretsError::Denied`] if it refused,
    /// [`SecretsError::Ambiguous`] if more than one stored item matches.
    fn get(&self, account: Uuid, kind: SecretKind) -> Result<Option<Secret>, SecretsError>;

    /// Write a secret, replacing whatever was stored for this account and kind.
    ///
    /// # Errors
    /// As [`SecretStore::get`].
    fn set(&self, account: Uuid, kind: SecretKind, value: Secret) -> Result<(), SecretsError>;

    /// Delete a secret. Deleting one that is not there is `Ok(())`.
    ///
    /// # Errors
    /// As [`SecretStore::get`].
    fn delete(&self, account: Uuid, kind: SecretKind) -> Result<(), SecretsError>;

    /// Report which store this is and what condition it is in, without reading, writing, or raising
    /// an unlock prompt.
    fn probe(&self) -> BackendReport;

    /// Delete every secret stored for `account`, whatever kinds it has.
    ///
    /// Every kind is attempted even after one of them fails, and the first failure is reported once
    /// the sweep is over. Stopping at the first would leave the rest of the account's secrets in a
    /// store the user asked to be emptied, which is the residue this exists to prevent; the caller
    /// still learns that the sweep was not clean.
    ///
    /// # Errors
    /// As [`SecretStore::delete`], for the first kind that failed.
    fn forget_account(&self, account: Uuid) -> Result<(), SecretsError> {
        let mut first = None;
        for kind in SecretKind::ALL {
            if let Err(err) = self.delete(account, kind) {
                first.get_or_insert(err);
            }
        }
        first.map_or(Ok(()), Err)
    }
}

/// The concrete secret store the composition root holds, wrapping one chosen backend.
pub struct Secrets {
    backend: Box<dyn SecretStore + Send + Sync>,
}

impl Secrets {
    /// Wrap the default backend.
    ///
    /// Infallible, and does no I/O: a launcher that could not start because no keyring was running
    /// would be unusable offline. Detection happens in [`SecretStore::probe`], at the point a secret
    /// is actually wanted.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: Box::new(OsKeyring::new()),
        }
    }

    /// Wrap a backend the caller chose, rather than the platform default.
    ///
    /// The choice is the composition root's: this is how a user who has turned storage off, or who
    /// picked the fallback, gets the store that matches. Nothing here probes to make the decision,
    /// for the same reason [`Secrets::new`] does not.
    #[must_use]
    pub fn with_backend(backend: Box<dyn SecretStore + Send + Sync>) -> Self {
        Self { backend }
    }

    /// Borrow the active backend.
    #[must_use]
    pub fn store(&self) -> &(dyn SecretStore + Send + Sync) {
        self.backend.as_ref()
    }
}

impl Default for Secrets {
    fn default() -> Self {
        Self::new()
    }
}
