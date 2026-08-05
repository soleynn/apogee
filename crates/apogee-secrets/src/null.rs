//! The store that keeps nothing.

use uuid::Uuid;

use crate::{Backend, BackendReport, BackendState, Secret, SecretKind, SecretStore, SecretsError};

/// The backend for an account whose secrets are never to be written down.
///
/// It is a real store rather than an absent one so that the choice travels with the same seam as
/// every other: a caller does not branch on whether storage is configured, it asks the store it was
/// given and handles the answer.
///
/// The asymmetry between the three operations is deliberate. A read answering nothing and a delete
/// succeeding are both true statements about a store that holds nothing, and a caller acts on them
/// exactly as it would against a platform store that happens to be empty. A write is refused rather
/// than silently dropped, because a caller that believed it had saved a password would stop asking
/// for one and then fail to log in with no way to see why.
#[derive(Debug, Default)]
pub struct Null;

impl Null {
    /// Construct the store that keeps nothing.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SecretStore for Null {
    fn get(&self, _account: Uuid, _kind: SecretKind) -> Result<Option<Secret>, SecretsError> {
        Ok(None)
    }

    fn set(&self, _account: Uuid, _kind: SecretKind, _value: Secret) -> Result<(), SecretsError> {
        Err(SecretsError::NotStoring)
    }

    fn delete(&self, _account: Uuid, _kind: SecretKind) -> Result<(), SecretsError> {
        Ok(())
    }

    fn probe(&self) -> BackendReport {
        BackendReport {
            backend: Backend::Null,
            state: BackendState::NotStoring,
            sandbox: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: Uuid = Uuid::from_u128(0x0194_8f2c_7d3e_4a51_9b60_c2e8_1f45_a903);

    /// A write has to fail, and it has to fail as its own condition. Reported as `Denied` it would
    /// send the shell to tell the user about a sandbox permission they never set; reported as
    /// success it would lose the password without saying so.
    #[test]
    fn a_write_is_refused_as_its_own_condition() {
        let err = Null.set(ACCOUNT, SecretKind::Password, Secret::new(b"pw".to_vec()));
        assert!(matches!(err, Err(SecretsError::NotStoring)));
    }

    /// Reads and deletes are not failures. A caller sweeping an account it never stored anything for
    /// must not be handed an error it would have to special-case.
    #[test]
    fn reading_and_deleting_answer_as_an_empty_store() {
        for kind in SecretKind::ALL {
            assert!(Null.get(ACCOUNT, kind).expect("read").is_none());
            Null.delete(ACCOUNT, kind).expect("delete");
        }
        Null.forget_account(ACCOUNT).expect("sweep");
    }

    /// `is_usable` decides whether a caller offers to save at all. True here would mean offering,
    /// then refusing the write that followed.
    #[test]
    fn the_report_names_the_store_and_refuses_to_look_usable() {
        let report = Null.probe();
        assert_eq!(report.backend, Backend::Null);
        assert_eq!(report.state, BackendState::NotStoring);
        assert!(!report.is_usable());
        assert!(!report.locked());
        assert!(report.sandbox.is_none());
    }
}
