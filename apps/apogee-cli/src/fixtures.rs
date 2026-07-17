//! Test-only substitution of a scripted login transport, gated behind the `fixtures` feature so it
//! is never in a release build. When `APOGEE_FIXTURE_LOGIN=current` is set, the CLI drives a canned
//! successful login → current-game registration instead of the network, while the launch backend
//! stays real. This is what makes the end-to-end launch test hermetic.

use std::sync::Arc;

use apogee_core::{Secret, Transport};
use apogee_test_support::login_fixtures as fx;
use apogee_test_support::transport::FixtureTransport;

/// The scripted transport to inject, or `None` to use the real network.
pub(crate) fn transport() -> Option<Arc<dyn Transport>> {
    match std::env::var("APOGEE_FIXTURE_LOGIN").ok().as_deref() {
        Some("current") => Some(Arc::new(FixtureTransport::new([
            fx::login_status_open(),
            fx::oauth_top("STOREDBLOB"),
            fx::submit_success("FIXTURE-SID", 3, 1),
            fx::register_current("FIXTURE-UID"),
        ]))),
        _ => None,
    }
}

/// A canned password so the e2e test needs no terminal prompt. `None` outside fixture mode.
pub(crate) fn password() -> Option<Secret> {
    std::env::var_os("APOGEE_FIXTURE_LOGIN").map(|_| Secret::new(b"fixture".to_vec()))
}
