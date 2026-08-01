//! The two backends that are still shape only.

use uuid::Uuid;

use crate::{BackendReport, Secret, SecretKind, SecretStore, SecretsError};

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

/// No-op backend: reads return nothing, writes are refused (the deliberate narrowing).
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
