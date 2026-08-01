//! Probing a Secret Service whose collection is locked.
//!
//! Its own binary, and its own CI step on a keyring nothing else uses, because locking is one-way
//! here: unlocking again needs a prompt a headless session cannot answer.
//!
//! Only the probe is exercised. Every *store operation* against a locked collection searches it
//! first, and that raises the platform's unlock prompt and blocks until something dismisses it,
//! which on one machine took 0.6 seconds, 2.4 seconds, and once over two minutes for the same call.
//! Nothing that unpredictable belongs in a job that has to finish. The probe itself is prompt-free
//! by construction, measured at under 10ms across every run: it resolves the collection and reads
//! its `Locked` property, and neither call touches a secret.
//!
//! The classifications for the operations behind a lock are pinned in the crate's own unit tests,
//! where the errors are built directly. The downcast those classifications depend on is checked
//! against a live bus by `probe_no_backend` and `probe_no_collection`, both of which assert a
//! specific condition that is only reachable when it works.

use apogee_secrets::{BackendState, OsKeyring, SecretStore};
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;

#[test]
fn a_locked_store_probes_locked_and_stays_usable() {
    SecretService::connect(EncryptionType::Dh)
        .expect("connect to the bus")
        .get_any_collection()
        .expect("a collection")
        .lock()
        .expect("lock the collection");

    let report = OsKeyring::new().probe();

    assert_eq!(report.state, BackendState::Locked, "{report:?}");
    assert!(report.locked());
    // A locked store is still worth writing to: the write raises the platform's unlock prompt and
    // then succeeds. Reporting it as unusable would push a caller to the fallback for a keyring that
    // works perfectly well once the user types their password.
    assert!(report.is_usable());
}
