//! Reporting the Credential Manager's or the Keychain's condition.
//!
//! Neither store publishes its state the way a bus does, so the probe asks for a key that is never
//! written and reads the refusal. A miss means the store answered, which is all "reachable" means
//! here. Nothing is ever written, so the probe cannot create the entry it is looking for.
//!
//! No CI job runs this: both stores need their own operating system, and the workspace's hermetic
//! jobs have neither. It is exercised by the manual pre-release pass.

use keyring::Entry;

use crate::keyring_store::{BACKEND, SERVICE};
use crate::{BackendReport, BackendState};

/// A key nothing ever writes. Reading it asks the store to answer without changing anything.
const PROBE_KEY: &str = "probe";

pub(crate) fn probe() -> BackendReport {
    BackendReport {
        backend: BACKEND,
        state: probe_state(),
        // Neither platform has the sandbox this reports on.
        sandbox: None,
    }
}

fn probe_state() -> BackendState {
    match Entry::new(SERVICE, PROBE_KEY).and_then(|entry| entry.get_secret()) {
        // The key is never written, so a miss is the expected healthy answer; a hit would mean
        // something else wrote it, and the store still answered.
        Ok(_) | Err(keyring::Error::NoEntry) => BackendState::Ready,
        // Windows raises this only when there is no credential store session at all. On macOS it
        // covers an unavailable, missing, invalid, or read-only keychain; keyring drops the code, so
        // the read-only case cannot be separated out here.
        Err(keyring::Error::NoStorageAccess(_)) => BackendState::NoProvider,
        Err(_) => BackendState::Unreachable,
    }
}
