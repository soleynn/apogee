//! The store against a Secret Service whose collection is locked.
//!
//! Its own binary, and its own CI step on a keyring nothing else uses, because locking is one-way
//! here: unlocking again needs a prompt a headless session cannot answer.
//!
//! Reads past the lock are deliberately absent. Resolving a stored item searches the collection,
//! which raises that prompt and then waits on it, so how long the call takes is a question about
//! the environment rather than about this crate. Their classifications are pinned in the crate's
//! own unit tests, where the errors are built directly.
//!
//! A write is here because it does not reach a prompt: the store refuses it outright. That refusal
//! is a distinct route from the read path, it carries an error name nothing else in the suite
//! exercises, and it went unclassified until a live run against a real keyring found it. The unit
//! test covering it can only check that name against this crate's own match, so this is the only
//! thing that would notice the store starting to say something else.

use apogee_secrets::{BackendState, OsKeyring, Secret, SecretKind, SecretStore, SecretsError};
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use uuid::Uuid;

/// The opt-in this test refuses to run without.
///
/// It locks whatever collection the bus hands it, and on a desktop session that is the user's real
/// login keyring. Locking it there is not a test artifact that goes away: everything else on the
/// machine that keeps a secret stops being able to read one, the unlock prompt starts appearing over
/// whatever the user was doing, and anything holding a token in there begins reporting it as
/// invalid rather than as locked. Feature-gating alone did not prevent that, because a single
/// `--all-features` run turns the gate on.
const LOCK_OPT_IN: &str = "APOGEE_KEYRING_LOCK_OK";

#[test]
fn a_locked_store_probes_locked_and_refuses_a_write_as_locked() {
    assert!(
        std::env::var_os(LOCK_OPT_IN).is_some(),
        "refusing to run: this test locks the session's keyring and cannot unlock it again. \
         Set {LOCK_OPT_IN}=1, and only against a throwaway keyring on a private bus \
         (the CI step for this shows the shape: XDG_DATA_HOME to a temp dir under dbus-run-session)."
    );

    SecretService::connect(EncryptionType::Dh)
        .expect("connect to the bus")
        .get_any_collection()
        .expect("a collection")
        .lock()
        .expect("lock the collection");

    let store = OsKeyring::new();

    let report = store.probe();
    assert_eq!(report.state, BackendState::Locked, "{report:?}");
    assert!(report.locked());
    // A locked store is still worth writing to: the write raises the platform's unlock prompt and
    // then succeeds. Reporting it as unusable would push a caller to the fallback for a keyring that
    // works perfectly well once the user types their password.
    assert!(report.is_usable());

    match store.set(
        Uuid::new_v4(),
        SecretKind::Password,
        Secret::new(b"correct horse".to_vec()),
    ) {
        Err(SecretsError::Locked) => {}
        Err(other) => panic!(
            "a locked collection classified a write as {other}, so either the store stopped saying \
             it is locked or the backend error the classification reads is out of reach"
        ),
        Ok(()) => panic!("a locked collection accepted a write"),
    }
}
