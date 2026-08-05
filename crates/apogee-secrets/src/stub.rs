//! The backend that is still shape only.

use uuid::Uuid;

use crate::{Backend, BackendReport, BackendState, Secret, SecretKind, SecretStore, SecretsError};

/// Opt-in fallback backend: an encrypted on-disk store, for a session with no platform store to
/// talk to.
///
/// Not built yet. It answers every call with a failure rather than panicking: this is a library, and
/// a `todo!()` reached through a trait object is a crash in whichever process happened to hold it.
/// A caller sees a store that cannot do anything, which is the truth, and one that
/// [`BackendReport::is_usable`](crate::BackendReport::is_usable) already reports as unusable, so
/// nothing routes a secret here by accident.
#[derive(Debug, Default)]
pub struct EncryptedFile;

impl EncryptedFile {
    /// Construct the encrypted-file backend.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SecretStore for EncryptedFile {
    fn get(&self, _account: Uuid, _kind: SecretKind) -> Result<Option<Secret>, SecretsError> {
        Err(SecretsError::Backend { step: "read" })
    }

    fn set(&self, _account: Uuid, _kind: SecretKind, _value: Secret) -> Result<(), SecretsError> {
        Err(SecretsError::Backend { step: "store" })
    }

    fn delete(&self, _account: Uuid, _kind: SecretKind) -> Result<(), SecretsError> {
        Err(SecretsError::Backend { step: "delete" })
    }

    /// `Unreachable` rather than one of the conditions that names a cause: the store is not absent
    /// from the machine, nor locked, nor hidden by a sandbox. There is nothing on the other end yet,
    /// and inventing a cause would have the shell explain a problem the user cannot act on.
    fn probe(&self) -> BackendReport {
        BackendReport {
            backend: Backend::EncryptedFile,
            state: BackendState::Unreachable,
            sandbox: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: Uuid = Uuid::from_u128(0x0194_8f2c_7d3e_4a51_9b60_c2e8_1f45_a903);

    /// Reaching an unbuilt backend must not take the process down with it. The sweep is included
    /// because its default body calls `delete` twice, and a panic there would surface on a path a
    /// caller reaches while tidying up rather than while storing anything.
    #[test]
    fn every_call_fails_instead_of_panicking() {
        assert!(EncryptedFile.get(ACCOUNT, SecretKind::Password).is_err());
        assert!(
            EncryptedFile
                .set(ACCOUNT, SecretKind::Password, Secret::new(Vec::new()))
                .is_err()
        );
        assert!(EncryptedFile.delete(ACCOUNT, SecretKind::Password).is_err());
        assert!(EncryptedFile.forget_account(ACCOUNT).is_err());
        assert!(!EncryptedFile.probe().is_usable());
    }
}
