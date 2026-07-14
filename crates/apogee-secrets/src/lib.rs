#![forbid(unsafe_code)]
//! OS keyring-backed storage for account secrets.
//!
//! STUB: public shape only (the [`SecretStore`] seam, [`Secret`], the error taxonomy, and the
//! [`Secrets`] handle the composition root holds); behavior is not yet built. Secrets are
//! account-scoped and zeroizing.

use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

/// Secret-backend failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretsError {
    #[error("secret store is locked")]
    Locked,
    #[error("no secret backend available")]
    NoBackend,
    #[error("access denied by the secret backend")]
    Denied,
    #[error("io error")]
    Io(#[from] std::io::Error),
}

/// Which secret is addressed for an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretKind {
    Password,
    TotpSecret,
    SessionId,
}

/// A secret value. Zeroized on drop; deliberately implements no `Debug`/`Display`/`Serialize`/`Clone`.
pub struct Secret(Vec<u8>);

impl Secret {
    /// Wrap raw secret bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes (write-only across the IPC boundary; callers must not persist them).
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// What backend answered a [`SecretStore::probe`] and whether it is usable.
#[derive(Debug, Clone)]
pub struct BackendReport {
    pub backend: &'static str,
    pub locked: bool,
    pub advice: Option<String>,
}

/// Account-scoped secret storage. Implementors: [`OsKeyring`] (default), [`EncryptedFile`]
/// (opt-in fallback), [`Null`].
pub trait SecretStore {
    fn get(&self, account: Uuid, kind: SecretKind) -> Result<Option<Secret>, SecretsError>;
    fn set(&self, account: Uuid, kind: SecretKind, value: Secret) -> Result<(), SecretsError>;
    fn delete(&self, account: Uuid, kind: SecretKind) -> Result<(), SecretsError>;
    fn probe(&self) -> BackendReport;
}

/// Default backend: the OS keyring / Secret Service.
#[derive(Debug, Default)]
pub struct OsKeyring;

impl OsKeyring {
    /// Construct the OS-keyring backend.
    pub fn new() -> Self {
        Self
    }
}

impl SecretStore for OsKeyring {
    fn get(&self, _account: Uuid, _kind: SecretKind) -> Result<Option<Secret>, SecretsError> {
        todo!("read a secret from the OS keyring")
    }
    fn set(&self, _account: Uuid, _kind: SecretKind, _value: Secret) -> Result<(), SecretsError> {
        todo!("write a secret to the OS keyring")
    }
    fn delete(&self, _account: Uuid, _kind: SecretKind) -> Result<(), SecretsError> {
        todo!("delete a secret from the OS keyring")
    }
    fn probe(&self) -> BackendReport {
        todo!("probe the OS keyring backend")
    }
}

/// Opt-in fallback backend: an encrypted on-disk store.
#[derive(Debug, Default)]
pub struct EncryptedFile;

impl SecretStore for EncryptedFile {
    fn get(&self, _account: Uuid, _kind: SecretKind) -> Result<Option<Secret>, SecretsError> {
        todo!("read a secret from the encrypted file store")
    }
    fn set(&self, _account: Uuid, _kind: SecretKind, _value: Secret) -> Result<(), SecretsError> {
        todo!("write a secret to the encrypted file store")
    }
    fn delete(&self, _account: Uuid, _kind: SecretKind) -> Result<(), SecretsError> {
        todo!("delete a secret from the encrypted file store")
    }
    fn probe(&self) -> BackendReport {
        todo!("probe the encrypted file backend")
    }
}

/// No-op backend: reads return nothing, writes are refused (the deliberate LSP narrowing).
#[derive(Debug, Default)]
pub struct Null;

impl SecretStore for Null {
    fn get(&self, _account: Uuid, _kind: SecretKind) -> Result<Option<Secret>, SecretsError> {
        todo!("null backend read")
    }
    fn set(&self, _account: Uuid, _kind: SecretKind, _value: Secret) -> Result<(), SecretsError> {
        todo!("null backend write is refused")
    }
    fn delete(&self, _account: Uuid, _kind: SecretKind) -> Result<(), SecretsError> {
        todo!("null backend delete")
    }
    fn probe(&self) -> BackendReport {
        todo!("probe the null backend")
    }
}

/// The concrete secret store the composition root holds (`apogee-core`'s `secrets` field). Wraps a
/// chosen [`SecretStore`] backend behind one owned type.
pub struct Secrets {
    backend: Box<dyn SecretStore + Send + Sync>,
}

impl Secrets {
    /// Detect and wrap the default backend.
    pub fn new() -> Self {
        Self {
            backend: Box::new(OsKeyring::new()),
        }
    }

    /// Borrow the active backend.
    pub fn store(&self) -> &(dyn SecretStore + Send + Sync) {
        self.backend.as_ref()
    }
}

impl Default for Secrets {
    fn default() -> Self {
        Self::new()
    }
}
