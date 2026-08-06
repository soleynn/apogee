//! Whether a Keychain failure is a keychain that is merely shut.
//!
//! keyring maps five `OSStatus` values and boxes every other one inside `PlatformFailure`, which
//! this crate would otherwise report as an unclassified failure. Three of the values it does not map
//! mean "the keychain is there, it is shut, and a user can open it", and telling a caller that a
//! working store is broken sends them to the fallback or to keeping nothing.
//!
//! Split in two on purpose. Which codes mean what is a table, and it is checked by tests that run on
//! every host, including the ones with no Keychain at all: no job in this repository has Apple
//! hardware, so a table only Apple could execute is a table nothing holds. Reading the code out of
//! the error is the half that needs the platform, and it is one downcast.

/// `errSecInteractionNotAllowed`: the item is there and the keychain will not open it without asking
/// a user, in a process that may not ask. An ssh session, a launch daemon, a login hook.
const INTERACTION_NOT_ALLOWED: i32 = -25308;

/// `errSecAuthFailed`: the keychain asked and was answered wrongly. Still a keychain that opens.
const AUTH_FAILED: i32 = -25293;

/// `errSecUserCanceled`: the keychain asked and the user dismissed it. The Secret Service's
/// `Prompt`, which this crate already reads as a lock rather than as a failure.
const USER_CANCELED: i32 = -128;

/// Whether `err` is the keychain refusing until it is unlocked, rather than failing.
///
/// False on every target that cannot read a status, which is the answer that changes nothing: the
/// callers keep the classification they had before this existed.
pub(crate) fn locked(err: &keyring::Error) -> bool {
    status(err).is_some_and(is_locked)
}

/// The status table itself.
///
/// Everything outside it stays unclassified deliberately. An entitlement this build does not carry,
/// a parameter the framework rejected and a keychain that is genuinely damaged are not fixed by
/// unlocking, and folding them in would tell a user to unlock a store that is already open.
fn is_locked(status: i32) -> bool {
    matches!(
        status,
        INTERACTION_NOT_ALLOWED | AUTH_FAILED | USER_CANCELED
    )
}

/// The `OSStatus` keyring boxed inside its own error.
///
/// `None` for good if keyring's macOS `security-framework` major ever drifts from the one this crate
/// resolves, because a failed downcast is silent. That is why the audit script asserts the two agree
/// rather than leaving it to a test no host here can run.
#[cfg(target_os = "macos")]
fn status(err: &keyring::Error) -> Option<i32> {
    use std::error::Error as _;

    let code = err
        .source()?
        .downcast_ref::<security_framework::base::Error>()?
        .code();
    Some(code)
}

/// As above, on a target with no reader for one: every target but macOS. keyring resolves a
/// different major of the framework crate on iOS, and the Credential Manager has no status of this
/// shape at all.
#[cfg(not(target_os = "macos"))]
fn status(_err: &keyring::Error) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three the keychain answers with when it is shut. Frozen against literals rather than
    /// against the constants, because the constants are the thing under test: a typo in one of them
    /// is a build that reports a working keychain as broken, on hardware nothing here owns.
    #[test]
    fn a_shut_keychain_is_locked() {
        assert!(is_locked(-25308), "errSecInteractionNotAllowed");
        assert!(is_locked(-25293), "errSecAuthFailed");
        assert!(is_locked(-128), "errSecUserCanceled");
    }

    /// Nothing else is. The first two are codes keyring maps itself, so reading them as a lock would
    /// contradict it; the rest are failures no unlock fixes.
    #[test]
    fn nothing_else_is_a_lock() {
        for status in [
            -25291, // errSecNotAvailable, which keyring maps to NoStorageAccess
            -25300, // errSecItemNotFound, which keyring maps to NoEntry
            -25299, // errSecDuplicateItem
            25293,  // errSecAuthFailed with its sign lost
            -34018, // errSecMissingEntitlement
            -50,    // errSecParam
            0,
        ] {
            assert!(!is_locked(status), "{status}");
        }
    }

    /// On a target with no reader nothing is reclassified, so every caller keeps the answer it gave
    /// before the table existed.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_target_without_a_reader_reclassifies_nothing() {
        assert!(!locked(&keyring::Error::NoEntry));
        assert!(!locked(&keyring::Error::PlatformFailure(Box::new(
            std::io::Error::other("whatever the platform said")
        ))));
    }
}
