//! Reporting the Credential Manager's or the Keychain's condition.
//!
//! Neither store publishes its state the way a bus does, so the probe asks for a key that is never
//! written and reads the refusal. A miss means the store answered, which is all "reachable" means
//! here. Nothing is ever written, so the probe cannot create the entry it is looking for.
//!
//! No CI job runs this: both stores need their own operating system, and the workspace's hermetic
//! jobs have neither. It is exercised by the manual pre-release pass. A cross-target check job does
//! compile it, and the status table the classification below reads is tested on every host.

use crate::keyring_store::{BACKEND, SERVICE, open};
use crate::{BackendReport, BackendState};

/// A key nothing ever writes. Reading it asks the store to answer without changing anything.
const PROBE_KEY: &str = "probe";

pub(crate) fn probe() -> BackendReport {
    // Neither platform has the sandbox this reports on, which is what the bare constructor says.
    BackendReport::new(BACKEND, probe_state())
}

fn probe_state() -> BackendState {
    classify(
        open()
            .and_then(|store| store.build(SERVICE, PROBE_KEY, None))
            .and_then(|entry| entry.get_secret()),
    )
}

/// What the store's answer to that read says about its condition.
///
/// Split from the read so the truth table is a value rather than a machine: the read needs one of
/// two operating systems, and the table needs none.
fn classify(answer: Result<Vec<u8>, keyring_core::Error>) -> BackendState {
    match answer {
        // The key is never written, so a miss is the expected healthy answer; a hit would mean
        // something else wrote it, and the store still answered.
        Ok(_) | Err(keyring_core::Error::NoEntry) => BackendState::Ready,
        // Windows raises this only when there is no credential store session at all. On macOS it
        // covers an unavailable, missing, invalid, or read-only keychain, plus a write-permissions
        // refusal; the store boxes the code rather than reporting it, so the read-only case cannot be
        // separated out here.
        Err(keyring_core::Error::NoStorageAccess(_)) => BackendState::NoProvider,
        // A keychain that is shut rather than broken. It is worth writing to: the write raises the
        // unlock prompt and then succeeds, so reporting it as unreachable makes `is_usable()` false
        // and sends a front end to the fallback, or to keeping nothing, over a store that works
        // after one unlock. The Credential Manager has no lock and produces no such status.
        Err(err) if crate::apple::locked(&err) => BackendState::Locked,
        Err(_) => BackendState::Unreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_that_answers_at_all_is_ready() {
        assert_eq!(classify(Ok(Vec::new())), BackendState::Ready);
        assert_eq!(
            classify(Err(keyring_core::Error::NoEntry)),
            BackendState::Ready
        );
    }

    #[test]
    fn no_storage_access_is_no_provider() {
        let err =
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("no session")));
        assert_eq!(classify(Err(err)), BackendState::NoProvider);
    }

    /// A failure with no status this crate can read stays unclassified rather than being guessed at
    /// as a lock, which would tell a user to unlock a store that is not shut.
    #[test]
    fn a_failure_with_no_readable_status_is_unreachable() {
        let err =
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("something")));
        assert_eq!(classify(Err(err)), BackendState::Unreachable);
    }

    /// The whole path a shut keychain takes, through the downcast rather than through the status
    /// table alone. Compiled by the Apple cross-check job and run by nothing in this repository:
    /// there is no Apple host here, and this is the one case that needs the framework's own error
    /// type to exist.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_shut_keychain_is_locked_and_therefore_still_usable() {
        for code in [-25308, -25293, -128] {
            let err = keyring_core::Error::PlatformFailure(Box::new(
                security_framework::base::Error::from_code(code),
            ));
            assert_eq!(classify(Err(err)), BackendState::Locked, "{code}");
        }
        let report = BackendReport::new(BACKEND, BackendState::Locked);
        assert!(report.is_usable());
    }
}
