//! The storage seam and the handle the composition root holds.

use std::sync::Arc;

use uuid::Uuid;

use crate::{BackendReport, OsKeyring, Secret, SecretKind, SecretsError};

/// Refuse a value holding no bytes, before any store is asked to keep one.
///
/// Called from each backend's `set` rather than wrapped around the seam, because a caller holds a
/// `&dyn SecretStore` and would walk straight past a wrapper. The rule is the one
/// [`crate::EncryptedFile::create`] already applies to a passphrase, for the same reason
/// [`crate::Null`] refuses every write: a store that takes nothing and hands nothing back is
/// indistinguishable from one holding a real secret, so a front end renders the account as saved and
/// stops asking, the login submits an empty password, and it fails at the far end with an error that
/// says nothing about the store.
///
/// A one-byte secret is accepted, deliberately. How weak a password may be is not this crate's
/// question; whether there is one at all is.
///
/// # Errors
/// [`SecretsError::Empty`].
pub(crate) fn refuse_empty(value: &Secret) -> Result<(), SecretsError> {
    if value.is_empty() {
        return Err(SecretsError::Empty);
    }
    Ok(())
}

/// Account-scoped secret storage.
///
/// Every method blocks and may raise the platform's unlock prompt, so a caller on an async runtime
/// must wrap the call in `tokio::task::spawn_blocking`.
///
/// # Examples
/// A backend of a caller's own is the four methods without defaults. The probe is the one that
/// needs something from this crate, and [`BackendReport::new`] is it: the report is
/// `#[non_exhaustive]`, so a struct literal does not reach across a crate boundary.
/// ```
/// use std::sync::Arc;
///
/// use apogee_secrets::{
///     Backend, BackendReport, BackendState, Secret, SecretKind, SecretStore, Secrets, SecretsError,
/// };
/// use uuid::Uuid;
///
/// /// A store that answers every read with nothing and refuses every write.
/// struct KeepsNothing;
///
/// impl SecretStore for KeepsNothing {
///     fn get(&self, _: Uuid, _: SecretKind) -> Result<Option<Secret>, SecretsError> {
///         Ok(None)
///     }
///     fn set(&self, _: Uuid, _: SecretKind, _: Secret) -> Result<(), SecretsError> {
///         Err(SecretsError::NotStoring)
///     }
///     fn delete(&self, _: Uuid, _: SecretKind) -> Result<(), SecretsError> {
///         Ok(())
///     }
///     fn probe(&self) -> BackendReport {
///         BackendReport::new(Backend::Null, BackendState::NotStoring)
///     }
/// }
///
/// let secrets = Secrets::with_backend(Arc::new(KeepsNothing));
/// assert!(!secrets.store().probe().is_usable());
/// assert!(secrets.store().get(Uuid::nil(), SecretKind::Password)?.is_none());
/// # Ok::<(), SecretsError>(())
/// ```
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

    /// Report which store this is and what condition it is in.
    ///
    /// Answering costs I/O, and how much varies by backend: a bus call and a lock-state read, a read
    /// of a credential key nothing ever writes, a read of the sealed file's header. What holds
    /// everywhere is that no stored secret is read, nothing is written, and no unlock prompt is
    /// raised, so this is safe to call on every launch.
    fn probe(&self) -> BackendReport;

    /// Erase whatever this store is holding so it does not have to ask again, at the cost of asking
    /// again next time.
    ///
    /// The default does nothing, which is the honest answer for a store that keeps nothing between
    /// calls: the platform stores hold no key of their own, and [`crate::Null`] has nothing to hold.
    /// [`crate::EncryptedFile`] keeps the key its passphrase derives, and this is how a front end
    /// that knows the key is not wanted again (the session ended, the screen locked) shortens how
    /// long it is in this process's memory instead of waiting out that store's own idle window.
    fn seal(&self) {}

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
///
/// The backend is held behind a reference count so a subsystem that has to read a secret from a
/// thread of its own can be handed a share of the one store rather than a borrow of it.
pub struct Secrets {
    backend: Arc<dyn SecretStore + Send + Sync>,
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
            backend: Arc::new(OsKeyring::new()),
        }
    }

    /// Wrap a backend the caller chose, rather than the platform default.
    ///
    /// The choice is the composition root's: this is how a user who has turned storage off, or who
    /// picked the fallback, gets the store that matches. Nothing here probes to make the decision,
    /// for the same reason [`Secrets::new`] does not.
    ///
    /// Takes the share rather than the box. The handle holds its backend behind a reference count
    /// either way, so an owning box only means the caller cannot keep a handle on what it just
    /// injected: a test that wants to read back what the store was asked has to wrap it in a
    /// forwarding type first, and a forwarding type that forgets to pass [`SecretStore::seal`] on
    /// is a bug nothing catches.
    #[must_use]
    pub fn with_backend(backend: Arc<dyn SecretStore + Send + Sync>) -> Self {
        Self { backend }
    }

    /// Borrow the active backend.
    #[must_use]
    pub fn store(&self) -> &(dyn SecretStore + Send + Sync) {
        self.backend.as_ref()
    }

    /// A share of the active backend.
    ///
    /// What a subsystem takes when it has to reach the store from somewhere a borrow cannot go: a
    /// blocking task, which is where every read belongs, owns what it reads from for as long as it
    /// runs. It is the same backend, not a copy, so a store that keeps a derived key keeps one.
    #[must_use]
    pub fn shared(&self) -> Arc<dyn SecretStore + Send + Sync> {
        Arc::clone(&self.backend)
    }
}

impl Default for Secrets {
    fn default() -> Self {
        Self::new()
    }
}
