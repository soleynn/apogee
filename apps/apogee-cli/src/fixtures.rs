//! Test-only substitution of a scripted login transport, gated behind the `fixtures` feature so it
//! is never in a release build. When `APOGEE_FIXTURE_LOGIN=current` is set, the CLI drives a canned
//! successful login → current-game registration instead of the network, while the launch backend
//! stays real. This is what makes the end-to-end launch test hermetic.

use std::sync::Arc;

use apogee_core::{Secret, Transport};
use apogee_test_support::login_fixtures as fx;
use apogee_test_support::transport::FixtureTransport;

/// The scripted transport to inject, or `None` to use the real network.
///
/// `APOGEE_FIXTURE_LOGIN=current` scripts a login → current-boot check → current-game registration
/// (the launch e2e). `APOGEE_FIXTURE_LOGIN=patch` scripts a login → current-boot check →
/// pending-game-patch → current registration for the patch e2e: the single pending entry is read from
/// the file named by `APOGEE_FIXTURE_PATCH_ENTRY` (a nine-field patchlist line the test builds with
/// real per-block hashes and the chaos-server URL), and `APOGEE_FIXTURE_MAXEX` sets the reported max
/// expansion.
///
/// The boot check precedes registration in every patching flow, so it is scripted once, ahead of the
/// register responses. Omitting it would feed the game patchlist to the boot check, which would apply
/// it as a boot patch.
pub(crate) fn transport() -> Option<Arc<dyn Transport>> {
    match std::env::var("APOGEE_FIXTURE_LOGIN").ok().as_deref() {
        Some("current") => Some(Arc::new(FixtureTransport::new([
            fx::login_status_open(),
            fx::oauth_top("STOREDBLOB"),
            fx::submit_success("FIXTURE-SID", 3, 1),
            fx::boot_current(),
            fx::register_current("FIXTURE-UID"),
        ]))),
        Some("patch") => {
            // The pending patchlist entry the test wrote; an absent/unreadable file yields an empty
            // entry, which fails the patchlist parse loudly rather than silently skipping the patch.
            let entry = std::env::var("APOGEE_FIXTURE_PATCH_ENTRY")
                .ok()
                .and_then(|path| std::fs::read_to_string(path).ok())
                .map(|body| body.trim().to_owned())
                .unwrap_or_default();
            let max_expansion = std::env::var("APOGEE_FIXTURE_MAXEX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            Some(Arc::new(FixtureTransport::new([
                fx::login_status_open(),
                fx::oauth_top("STOREDBLOB"),
                fx::submit_success("FIXTURE-SID", 3, max_expansion),
                fx::boot_current(),
                fx::register_with_patches("FIXTURE-UID", &[&entry]),
                fx::register_current("FIXTURE-UID"),
            ])))
        }
        _ => None,
    }
}

/// A canned password so the e2e test needs no terminal prompt. `None` outside fixture mode.
pub(crate) fn password() -> Option<Secret> {
    std::env::var_os("APOGEE_FIXTURE_LOGIN").map(|_| Secret::new(b"fixture".to_vec()))
}

/// A canned passphrase for the sealed secret file, so the end-to-end test drives it without a
/// terminal. `None` unless the variable is set, so an ordinary run always prompts.
pub(crate) fn passphrase() -> Option<Secret> {
    std::env::var("APOGEE_FIXTURE_PASSPHRASE")
        .ok()
        .filter(|text| !text.is_empty())
        .map(|text| Secret::new(text.into_bytes()))
}
