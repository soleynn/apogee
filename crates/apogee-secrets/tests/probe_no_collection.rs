//! The store against a provider that has never been initialized.
//!
//! Its own CI step, on a keyring daemon started without unlocking anything, so no login keyring is
//! ever created and the default alias does not resolve. This is what a passwordless or autologin
//! session leaves behind, and it is the shape that reads as healthy if the probe is not careful:
//! the in-memory session collection is always present and always unlocked, so a probe that accepts
//! any collection reports a working store while every read and write fails.

use apogee_secrets::{BackendState, OsKeyring, Secret, SecretKind, SecretStore, SecretsError};
use uuid::Uuid;

#[test]
fn a_store_with_no_default_collection_says_so_rather_than_looking_healthy() {
    let store = OsKeyring::new();

    let report = store.probe();
    assert_eq!(
        report.state,
        BackendState::NoDefaultCollection,
        "an uninitialized keyring must not report as usable: {report:?}"
    );
    assert!(!report.is_usable());
    assert!(!report.locked());
}

/// The condition has to be its own answer, not a lock. A caller told "locked" would send the user
/// to type a password that unlocks nothing, and it would keep doing so forever.
#[test]
fn reads_and_writes_report_the_missing_collection_rather_than_a_lock() {
    let store = OsKeyring::new();
    let account = Uuid::new_v4();

    match store.set(
        account,
        SecretKind::Password,
        Secret::new(b"correct horse".to_vec()),
    ) {
        Err(SecretsError::NoCollection) => {}
        Err(other) => panic!("a store with no collection classified a write as: {other}"),
        Ok(()) => panic!("a store with no collection accepted a write"),
    }

    match store.get(account, SecretKind::Password) {
        Err(SecretsError::NoCollection) => {}
        Err(other) => panic!("a store with no collection classified a read as: {other}"),
        Ok(_) => panic!("a store with no collection answered a read"),
    }
}
