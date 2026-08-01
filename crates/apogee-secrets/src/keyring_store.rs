//! The platform credential store.

use keyring::Entry;
use uuid::Uuid;

use crate::{Backend, BackendReport, Secret, SecretKind, SecretStore, SecretsError};

/// The service half of every stored key. Constant across accounts and platforms.
pub(crate) const SERVICE: &str = "apogee";

/// Which store this build talks to.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
pub(crate) const BACKEND: Backend = Backend::SecretService;
#[cfg(target_os = "windows")]
pub(crate) const BACKEND: Backend = Backend::WindowsCredentialManager;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) const BACKEND: Backend = Backend::AppleKeychain;

/// Default backend: the platform credential store.
#[derive(Debug, Default)]
pub struct OsKeyring;

impl OsKeyring {
    /// Construct the platform credential store backend.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// The user half of a stored key: the account and what the secret is, under one service.
///
/// Only `Entry::new` is used, on every platform. `new_with_target`'s third argument means three
/// different things across the three stores (a collection to create, the sole Credential Manager
/// lookup key, a Keychain domain that rejects anything but four reserved words), so a build that
/// used it would take a code path no other platform's CI could execute.
///
/// The result is injective: a hyphenated UUID is 36 characters of `[0-9a-f-]` and contains no
/// separator, so no account and kind pair can collide with another.
fn key_for(account: Uuid, kind: SecretKind) -> String {
    format!("{}/{}", account.hyphenated(), kind.slug())
}

fn entry_for(account: Uuid, kind: SecretKind) -> Result<Entry, SecretsError> {
    Entry::new(SERVICE, &key_for(account, kind)).map_err(|err| map_error(&err, "address a secret"))
}

/// Fold a credential-store failure into the taxonomy, dropping the platform error.
///
/// The platform error is deliberately never carried: `keyring::Error::BadEncoding` holds the raw
/// secret bytes and the enum derives `Debug`, and `Ambiguous` formats the matched credentials, which
/// echoes the account. Either printed anywhere above this crate is the leak the crate exists to
/// prevent, so the error is matched here and dropped.
fn map_error(err: &keyring::Error, step: &'static str) -> SecretsError {
    match err {
        keyring::Error::Ambiguous(_) => SecretsError::Ambiguous,
        keyring::Error::NoStorageAccess(_) => no_storage_access(err, step),
        keyring::Error::PlatformFailure(_) => platform_failure(err, step),
        // `NoEntry` is answered by the callers, which turn it into an absence rather than a
        // failure. `TooLong`, `Invalid` and `BadEncoding` are unreachable with the keys and the
        // binary API this crate uses, and the enum is non-exhaustive besides.
        _ => SecretsError::Backend { step },
    }
}

/// A locked collection and a dismissed prompt mean the same thing to a caller: unlock and try
/// again. A collection that did not resolve does not, and must not be folded in with them.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn no_storage_access(err: &keyring::Error, step: &'static str) -> SecretsError {
    match source_error(err) {
        Some(secret_service::Error::Locked | secret_service::Error::Prompt) => SecretsError::Locked,
        Some(other) => classify_secret_service(other, step),
        None => SecretsError::Backend { step },
    }
}

/// Neither of these stores has a locked state that reaches here. On Windows this variant is only
/// ever `ERROR_NO_SUCH_LOGON_SESSION`, meaning there is no credential store session at all; on macOS
/// it covers an unavailable, missing, or invalid keychain, plus a read-only one. Keyring boxes the
/// platform error without the code, so the read-only case cannot be told from the other three and is
/// reported with them as no store rather than as a refusal.
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
fn no_storage_access(_err: &keyring::Error, _step: &'static str) -> SecretsError {
    SecretsError::NoBackend
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn platform_failure(err: &keyring::Error, step: &'static str) -> SecretsError {
    match source_error(err) {
        Some(inner) => classify_secret_service(inner, step),
        None => SecretsError::Backend { step },
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
fn platform_failure(_err: &keyring::Error, step: &'static str) -> SecretsError {
    SecretsError::Backend { step }
}

/// Reach the Secret Service error keyring boxed inside its own.
///
/// This returns `None` for good if keyring ever resolves to a different major version of the Secret
/// Service crate than this one does, which would quietly flatten every classification below into
/// `Backend`. The live integration test asserts the downcast still succeeds, because nothing about
/// that drift is a compile error.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn source_error(err: &keyring::Error) -> Option<&secret_service::Error> {
    use std::error::Error as _;
    err.source()?.downcast_ref::<secret_service::Error>()
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
pub(crate) fn classify_secret_service(
    err: &secret_service::Error,
    step: &'static str,
) -> SecretsError {
    use crate::probe::BusFailure;

    match crate::probe::bus_failure(err) {
        Some(BusFailure::NoName) => SecretsError::NoBackend,
        Some(BusFailure::Denied) => SecretsError::Denied,
        Some(BusFailure::Locked) => SecretsError::Locked,
        None => match err {
            secret_service::Error::Unavailable => SecretsError::NoBackend,
            secret_service::Error::Locked | secret_service::Error::Prompt => SecretsError::Locked,
            // Not a lock, and never produced by one. The store raises this when the collection the
            // store addresses does not resolve, which no amount of unlocking changes.
            secret_service::Error::NoResult => SecretsError::NoCollection,
            _ => SecretsError::Backend { step },
        },
    }
}

impl SecretStore for OsKeyring {
    fn get(&self, account: Uuid, kind: SecretKind) -> Result<Option<Secret>, SecretsError> {
        match entry_for(account, kind)?.get_secret() {
            Ok(bytes) => Ok(Some(Secret::new(bytes))),
            Err(keyring::Error::NoEntry) => Ok(None),
            // `get_secret` rather than `get_password`: the string reader is the one call that can
            // hand back an error carrying the raw secret when the stored bytes are not UTF-8.
            Err(err) => Err(map_error(&err, "read")),
        }
    }

    fn set(&self, account: Uuid, kind: SecretKind, value: Secret) -> Result<(), SecretsError> {
        entry_for(account, kind)?
            .set_secret(value.expose())
            .map_err(|err| map_error(&err, "store"))
    }

    fn delete(&self, account: Uuid, kind: SecretKind) -> Result<(), SecretsError> {
        match entry_for(account, kind)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(map_error(&err, "delete")),
        }
    }

    fn probe(&self) -> BackendReport {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
        {
            crate::probe::probe()
        }
        #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
        {
            crate::probe_native::probe()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: Uuid = Uuid::from_u128(0x0194_8f2c_7d3e_4a51_9b60_c2e8_1f45_a903);

    /// The key is the on-disk contract. A change to either half orphans every secret already stored
    /// under the old one, silently, so both halves are frozen here against a fixed account.
    #[test]
    fn stored_keys_are_frozen() {
        assert_eq!(SERVICE, "apogee");
        assert_eq!(
            key_for(ACCOUNT, SecretKind::Password),
            "01948f2c-7d3e-4a51-9b60-c2e81f45a903/password"
        );
        assert_eq!(
            key_for(ACCOUNT, SecretKind::TotpSecret),
            "01948f2c-7d3e-4a51-9b60-c2e81f45a903/totp"
        );
    }

    /// Two kinds under one account, and one kind under two accounts, must never produce the same
    /// key: the separator is what guarantees it, and a UUID cannot contain one.
    #[test]
    fn keys_do_not_collide() {
        let other = Uuid::from_u128(1);
        assert_ne!(
            key_for(ACCOUNT, SecretKind::Password),
            key_for(ACCOUNT, SecretKind::TotpSecret)
        );
        assert_ne!(
            key_for(ACCOUNT, SecretKind::Password),
            key_for(other, SecretKind::Password)
        );
    }

    /// A store error that reaches the caller as a rendered string must not carry anything the
    /// platform error had in it. The one that matters holds the raw secret bytes.
    #[test]
    fn a_mapped_error_never_renders_the_platform_error() {
        let leaky = keyring::Error::BadEncoding(b"hunter2".to_vec());
        let mapped = map_error(&leaky, "read");
        let rendered = format!("{mapped} {mapped:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(matches!(mapped, SecretsError::Backend { step: "read" }));
    }

    #[test]
    fn several_matching_items_are_their_own_condition() {
        let err = keyring::Error::Ambiguous(Vec::new());
        assert!(matches!(map_error(&err, "read"), SecretsError::Ambiguous));
    }

    /// Keyring's enum is non-exhaustive and three of its variants are unreachable with the keys and
    /// the binary API used here, so they all land on the catch-all rather than on a guess.
    #[test]
    fn unreachable_variants_land_on_the_catch_all() {
        let cases = [
            keyring::Error::TooLong("user".to_owned(), 512),
            keyring::Error::Invalid("service".to_owned(), "empty".to_owned()),
            keyring::Error::NoEntry,
        ];
        for err in cases {
            assert!(matches!(
                map_error(&err, "store"),
                SecretsError::Backend { step: "store" }
            ));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
    mod secret_service_mapping {
        use super::*;

        fn boxed(err: secret_service::Error) -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(err)
        }

        /// Both Secret Service errors that mean "unlock and try again" have to arrive as one
        /// condition: a caller that treated a dismissed prompt as a hard failure would push a user
        /// to the fallback for a keyring that works.
        #[test]
        fn locking_conditions_map_to_locked() {
            for err in [secret_service::Error::Locked, secret_service::Error::Prompt] {
                let outer = keyring::Error::NoStorageAccess(boxed(err));
                assert!(matches!(map_error(&outer, "read"), SecretsError::Locked));
            }
        }

        /// A collection that does not resolve is not a lock, and folding it in with one is a
        /// misdiagnosis a user cannot act on: a keyring that was never initialized has nothing to
        /// unlock, so it would sit there being told to unlock a store that is already open. The
        /// store raises this on a passwordless or autologin session, and it arrives under both of
        /// keyring's wrappers depending on which call reached it.
        #[test]
        fn an_unresolved_collection_is_not_a_lock() {
            for outer in [
                keyring::Error::NoStorageAccess(boxed(secret_service::Error::NoResult)),
                keyring::Error::PlatformFailure(boxed(secret_service::Error::NoResult)),
            ] {
                assert!(matches!(
                    map_error(&outer, "store"),
                    SecretsError::NoCollection
                ));
            }
        }

        #[test]
        fn no_bus_or_no_provider_maps_to_no_backend() {
            let outer = keyring::Error::PlatformFailure(boxed(secret_service::Error::Unavailable));
            assert!(matches!(map_error(&outer, "read"), SecretsError::NoBackend));

            let unknown = secret_service::Error::ZbusFdo(zbus::fdo::Error::ServiceUnknown(
                "org.freedesktop.secrets".to_owned(),
            ));
            let outer = keyring::Error::PlatformFailure(boxed(unknown));
            assert!(matches!(map_error(&outer, "read"), SecretsError::NoBackend));
        }

        /// A sandbox bus policy refusing the name is a different answer from the name not being
        /// there: one is fixed by a permission, the other by installing a keyring.
        #[test]
        fn a_refused_name_maps_to_denied() {
            let denied = secret_service::Error::ZbusFdo(zbus::fdo::Error::AccessDenied(
                "not allowed".to_owned(),
            ));
            let outer = keyring::Error::PlatformFailure(boxed(denied));
            assert!(matches!(map_error(&outer, "read"), SecretsError::Denied));
        }

        /// Keyring boxes the Secret Service error, and the downcast that reads it is silent when it
        /// fails. A source of another type must fall to the catch-all rather than be misread.
        #[test]
        fn an_unrecognized_source_falls_to_the_catch_all() {
            let outer = keyring::Error::PlatformFailure(Box::new(std::io::Error::other("other")));
            assert!(matches!(
                map_error(&outer, "read"),
                SecretsError::Backend { step: "read" }
            ));
        }
    }
}
