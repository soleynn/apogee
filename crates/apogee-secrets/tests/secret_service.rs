//! The store against a real Secret Service.
//!
//! Everything here needs a session bus with a provider on it, which is what the dedicated CI job
//! supplies. The unit tests classify errors; only a real provider produces them.
//!
//! Run single-threaded: the cases share one collection and one process-global credential builder.

use std::collections::HashMap;

use apogee_secrets::{BackendState, OsKeyring, Secret, SecretKind, SecretStore, SecretsError};
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use uuid::Uuid;

/// A fresh account per case, so a leftover item from an earlier run cannot make a case pass.
fn account() -> Uuid {
    Uuid::new_v4()
}

fn store() -> OsKeyring {
    OsKeyring::new()
}

#[test]
fn a_stored_secret_reads_back_and_deletes() {
    let store = store();
    let account = account();

    store
        .set(
            account,
            SecretKind::Password,
            Secret::new(b"correct horse".to_vec()),
        )
        .expect("store the secret");

    let read = store
        .get(account, SecretKind::Password)
        .expect("read the secret")
        .expect("the secret is there");
    assert_eq!(read.expose(), b"correct horse");

    store
        .delete(account, SecretKind::Password)
        .expect("delete the secret");
    assert!(
        store
            .get(account, SecretKind::Password)
            .expect("read after delete")
            .is_none()
    );
}

/// `keyring_core` ships an in-process mock store, and which store attaches is this crate's own
/// choice of dependency: a build that attached the mock passes every round-trip in this file while
/// saving nothing. Reading the item back off the bus, rather than through the same library that
/// wrote it, is what tells the two apart.
#[test]
fn the_secret_reaches_the_bus_and_not_a_process_local_store() {
    let store = store();
    let account = account();
    store
        .set(
            account,
            SecretKind::TotpSecret,
            Secret::new(b"JBSWY3DPEHPK3PXP".to_vec()),
        )
        .expect("store the secret");

    let service = SecretService::connect(EncryptionType::Dh).expect("connect to the bus");
    let user = format!("{}/totp", account.hyphenated());
    let attributes = HashMap::from([("service", "apogee"), ("username", user.as_str())]);
    let items = service.search_items(attributes).expect("search the bus");
    assert_eq!(
        items.unlocked.len(),
        1,
        "the item written through the store was not on the bus"
    );

    store
        .delete(account, SecretKind::TotpSecret)
        .expect("delete the secret");
}

/// A value with no bytes in it is refused here too.
///
/// The refusal is written into each backend's own `set` rather than wrapped around the seam, because
/// a caller holds a `&dyn SecretStore` and would walk straight past a wrapper. That is what makes it
/// three separate rules to keep rather than one, and this is the arm a real provider covers: an
/// empty item goes onto the bus and comes back off it perfectly well, so nothing downstream notices
/// that a front end has rendered the account as saved and stopped asking.
#[test]
fn a_secret_with_no_bytes_in_it_is_refused_rather_than_saved() {
    let store = store();
    let account = account();

    let err = store
        .set(account, SecretKind::Password, Secret::new(Vec::new()))
        .expect_err("an empty value must be refused");
    assert!(matches!(err, SecretsError::Empty), "{err:?}");

    assert!(
        store
            .get(account, SecretKind::Password)
            .expect("read after the refused write")
            .is_none(),
        "the refused write reached the store anyway"
    );

    // One byte is a bad password and a real one. Which is not this crate's call to make.
    store
        .set(account, SecretKind::Password, Secret::new(b"x".to_vec()))
        .expect("a one-byte secret is a secret");
    store
        .delete(account, SecretKind::Password)
        .expect("delete the secret");
}

#[test]
fn deleting_a_secret_that_was_never_stored_succeeds() {
    store()
        .delete(account(), SecretKind::Password)
        .expect("deleting an absent secret is not a failure");
}

#[test]
fn reading_a_secret_that_was_never_stored_is_an_absence() {
    let read = store()
        .get(account(), SecretKind::Password)
        .expect("reading an absent secret is not a failure");
    assert!(read.is_none());
}

#[test]
fn an_unlocked_store_probes_ready() {
    let report = store().probe();
    assert_eq!(report.state, BackendState::Ready, "{report:?}");
    assert_eq!(report.sandbox, None);
    assert!(report.is_usable());
    assert!(!report.locked());
}

// Nothing here locks the collection. Locking is one-way in a headless session: unlocking again needs
// a prompt nobody can answer, so a case that locked would leave every case after it facing a store
// it did not expect. The locked paths get their own process, in `secret_service_locked`.
