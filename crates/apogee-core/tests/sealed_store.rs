//! The Core-owned sealed-file lifecycle as driven by a consenting front end.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use apogee_core::{
    Account, AccountKind, Consent, Core, CoreConfig, EncryptedFile, FileState, KdfCost, Passphrase,
    Secret, SecretBackend, SecretKind, SecretsError, Settings,
};
use apogee_test_support::transport::FixtureTransport;

struct FixedPassphrase {
    prompts: AtomicUsize,
}

impl Passphrase for FixedPassphrase {
    fn unlock(&self) -> Result<Secret, SecretsError> {
        self.prompts.fetch_add(1, Ordering::Relaxed);
        Ok(Secret::new(b"sealed passphrase".to_vec()))
    }
}

/// The explicit unlock and the active encrypted backend must share one handle. Two independently
/// opened handles would make the mutation prompt again after the front end had already completed
/// the explicit unlock step.
#[test]
fn an_explicit_unlock_primes_the_active_backend() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::TempDir::new()?;
    let config = CoreConfig::with_base(dir.path());
    let passphrase = Arc::new(FixedPassphrase {
        prompts: AtomicUsize::new(0),
    });
    let transport = || Arc::new(FixtureTransport::new([]));
    EncryptedFile::open(config.secrets_path(), passphrase.clone()).create(
        Consent::granted(),
        &Secret::new(b"sealed passphrase".to_vec()),
        KdfCost::floor(),
    )?;
    let bootstrap =
        Core::with_transport_and_passphrase(config.clone(), transport(), passphrase.clone())?;
    bootstrap.save_settings(&Settings {
        secret_backend: SecretBackend::EncryptedFile,
        ..Settings::default()
    })?;
    drop(bootstrap);

    let core = Core::with_transport_and_passphrase(config, transport(), passphrase.clone())?;
    assert!(matches!(
        core.secrets_file_state(),
        FileState::Sealed { .. }
    ));
    assert!(!core.secrets_file_is_open());
    core.unlock_secrets_file()?;
    assert!(core.secrets_file_is_open());
    assert_eq!(passphrase.prompts.load(Ordering::Relaxed), 1);

    let account = Account::new("sealed", AccountKind::Standard);
    core.save_account(&account)?;
    core.store_secret(
        account.id,
        SecretKind::Password,
        Secret::new(b"password".to_vec()),
    )?;
    assert_eq!(
        passphrase.prompts.load(Ordering::Relaxed),
        1,
        "the write must reuse the explicitly primed key"
    );

    core.seal_secrets_file();
    assert!(!core.secrets_file_is_open());
    assert!(core.remove_secrets_file(Consent::granted())?);
    assert_eq!(core.secrets_file_state(), FileState::Absent);
    assert!(!core.secrets_file_is_open());
    Ok(())
}
