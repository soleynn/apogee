//! The probe on a session bus that cannot produce a credential store.
//!
//! This needs its own bus, which the CI job builds by pointing the daemon at an empty service
//! directory. Once a keyring is installed on the machine, a plain session bus activates it on
//! demand, so the only way to reach this path is a bus that has nothing to activate.

use apogee_secrets::{BackendState, OsKeyring, SecretKind, SecretStore, SecretsError};
use uuid::Uuid;

#[test]
fn a_bus_with_no_provider_probes_as_no_provider() {
    let report = OsKeyring::new().probe();
    assert_eq!(report.state, BackendState::NoProvider, "{report:?}");
    assert!(!report.is_usable());
    assert!(!report.locked());
}

/// The sandbox flag is what separates a missing keyring from a sandbox hiding one, so the case that
/// is genuinely missing a keyring has to report no sandbox. If this ever samples one, the two
/// conditions have collapsed into a single answer.
#[test]
fn a_missing_provider_is_not_reported_as_a_sandbox() {
    assert_eq!(OsKeyring::new().probe().sandbox, None);
}

/// The probe classifies; the store has to agree with it. A read against the same bus must fail as
/// no backend rather than as some unclassified backend failure.
#[test]
fn a_read_against_that_bus_fails_as_no_backend() {
    let read = OsKeyring::new().get(Uuid::new_v4(), SecretKind::Password);
    match read {
        Err(SecretsError::NoBackend) => {}
        Err(other) => panic!("a bus with no provider classified as: {other}"),
        Ok(_) => panic!("a bus with no provider answered a read"),
    }
}
