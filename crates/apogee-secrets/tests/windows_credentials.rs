//! Reading another launcher's password out of the Windows Credential Manager.
//!
//! The only place the target strings are proved against a real store. Everywhere else they are
//! frozen by unit tests, which show that this crate builds the string it means to build and nothing
//! about whether the platform looks a credential up by it.
//!
//! Needs credentials seeded by the CI job that runs this, with the platform's own tool rather than
//! through this crate: a fixture written by the code under test would agree with itself whatever
//! target it used.

#![cfg(target_os = "windows")]

use apogee_secrets::{ForeignCredentialStore, ForeignKey, ImportSource};

/// Seeded by the job as `XIVLAUNCHER-ci-current`.
const CURRENT: &str = "ci-current";

/// Seeded by the job as `FINAL FANTASY XIV-ci-legacy`, the prefix that launcher used before.
const LEGACY: &str = "ci-legacy";

#[test]
fn a_credential_under_the_current_target_is_found() {
    let found = ForeignCredentialStore::new()
        .password(&ForeignKey::from_stored_name(CURRENT))
        .expect("read the credential store")
        .expect("the seeded credential was not found");

    assert_eq!(found.expose(), b"current-password");
}

/// An install that has not been opened since that launcher changed prefixes still has its password
/// only under the old target, and its own reader still probes there first.
#[test]
fn a_credential_under_the_legacy_target_is_found() {
    let found = ForeignCredentialStore::new()
        .password(&ForeignKey::from_stored_name(LEGACY))
        .expect("read the credential store")
        .expect("the seeded legacy credential was not found");

    assert_eq!(found.expose(), b"legacy-password");
}

/// An account with nothing saved is an answer rather than a failure.
#[test]
fn an_account_with_nothing_saved_reads_as_nothing() {
    let found = ForeignCredentialStore::new()
        .password(&ForeignKey::from_stored_name("ci-never-saved-anything"))
        .expect("read the credential store");

    assert!(found.is_none());
}
