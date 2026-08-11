//! The platform credential store.

use std::sync::Arc;

use keyring_core::{CredentialStore, Entry};
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
/// No store modifiers are passed, on any platform. Each store reads its own set out of that map (a
/// collection to create, the sole Credential Manager lookup key, a Keychain domain that rejects
/// anything but four reserved words), so a build that set one would take a code path no other
/// platform's CI could execute.
///
/// The result is injective: a hyphenated UUID is 36 characters of `[0-9a-f-]` and contains no
/// separator, so no account and kind pair can collide with another.
fn key_for(account: Uuid, kind: SecretKind) -> String {
    format!("{}/{}", account.hyphenated(), kind.slug())
}

/// Attach this target's credential store.
///
/// Built here rather than installed once as `keyring_core`'s process-wide default, because that
/// default is a global a library has no business claiming: the last crate to set it wins for the
/// whole process, and this one is linked into a launcher that embeds others.
///
/// Rebuilt per operation rather than kept, because the store owns the live connection underneath it.
/// One held across a session bus restart addresses a socket nothing is listening on any more, and
/// every later call fails against it with no way to ask for a fresh one. Connecting per operation is
/// what the store layer this replaced did.
///
/// Raw rather than classified, because two callers read the store's own error instead of the
/// taxonomy: the native probe, whose whole answer is what the store said, and the reader for
/// credentials another launcher owns.
pub(crate) fn open() -> keyring_core::Result<Arc<CredentialStore>> {
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
    let built = zbus_secret_service_keyring_store::Store::new()?;
    #[cfg(target_os = "windows")]
    let built = windows_native_keyring_store::Store::new()?;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let built = apple_native_keyring_store::keychain::Store::new()?;

    Ok(built)
}

/// [`open`], with the failure folded into the taxonomy the rest of this file speaks. On Linux that
/// fold is the whole classification: a bus that is missing, refusing or holding no collection is
/// named here, at the connect, rather than arriving unlabelled from the operation that followed it.
fn store() -> Result<Arc<CredentialStore>, SecretsError> {
    open().map_err(|err| map_error(&err, "connect"))
}

fn entry_for(account: Uuid, kind: SecretKind) -> Result<Entry, SecretsError> {
    store()?
        .build(SERVICE, &key_for(account, kind), None)
        .map_err(|err| map_error(&err, "address a secret"))
}

/// Fold a credential-store failure into the taxonomy, dropping the platform error.
///
/// The platform error is deliberately never carried: `keyring_core::Error::BadEncoding` and
/// `BadDataFormat` both hold the raw secret bytes and the enum derives `Debug`, and `Ambiguous`
/// formats the matched credentials, which echoes the account. Any of them printed anywhere above this
/// crate is the leak the crate exists to prevent, so the error is matched here and dropped.
fn map_error(err: &keyring_core::Error, step: &'static str) -> SecretsError {
    match err {
        keyring_core::Error::Ambiguous(_) => SecretsError::Ambiguous,
        keyring_core::Error::NoStorageAccess(_) => no_storage_access(err, step),
        keyring_core::Error::PlatformFailure(_) => platform_failure(err, step),
        // `NoEntry` is answered by the callers, which turn it into an absence rather than a
        // failure. `TooLong`, `Invalid`, `BadEncoding` and `BadDataFormat` are unreachable with the
        // keys and the binary API this crate uses; `NoDefaultStore` is unreachable because entries
        // are built from an owned store rather than the process-wide one, and `NotSupportedByStore`
        // because nothing here calls an optional operation. The enum is non-exhaustive besides.
        _ => SecretsError::Backend { step },
    }
}

/// A locked collection and a dismissed prompt mean the same thing to a caller: unlock and try
/// again. A collection that did not resolve does not, and must not be folded in with them.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn no_storage_access(err: &keyring_core::Error, step: &'static str) -> SecretsError {
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
fn no_storage_access(_err: &keyring_core::Error, _step: &'static str) -> SecretsError {
    SecretsError::NoBackend
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn platform_failure(err: &keyring_core::Error, step: &'static str) -> SecretsError {
    match source_error(err) {
        Some(inner) => classify_secret_service(inner, step),
        None => SecretsError::Backend { step },
    }
}

/// The Keychain's lock arrives here, in the variant the store boxes everything it does not map into.
/// A locked store is answered by unlocking and retrying, so it must not be reported as a failure the
/// user can do nothing about. The Credential Manager has no lock and produces no status of this
/// shape, so nothing changes there.
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
fn platform_failure(err: &keyring_core::Error, step: &'static str) -> SecretsError {
    if crate::apple::locked(err) {
        SecretsError::Locked
    } else {
        SecretsError::Backend { step }
    }
}

/// Reach the Secret Service error the store boxed inside its own.
///
/// This returns `None` for good if the store crate ever resolves to a different major version of the
/// Secret Service crate than this one does, which would quietly flatten every classification below
/// into `Backend`. Nothing about that drift is a compile error, so it is asserted twice: off the
/// resolved graph by `scripts/audit.sh`, and against a real store by the live integration test.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn source_error(err: &keyring_core::Error) -> Option<&secret_service::Error> {
    use std::error::Error as _;
    err.source()?.downcast_ref::<secret_service::Error>()
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
pub(crate) fn classify_secret_service(
    err: &secret_service::Error,
    step: &'static str,
) -> SecretsError {
    use crate::probe::{BusFailure, is_dead_session_bus};

    match crate::probe::bus_failure(err) {
        Some(BusFailure::NoName) => SecretsError::NoBackend,
        Some(BusFailure::Denied) => SecretsError::Denied,
        Some(BusFailure::Locked) => SecretsError::Locked,
        // A socket that is there and will not take a connection: no store answered, exactly as
        // `Unavailable` below. The probe already names it and this path did not, so the same dead
        // bus reported as an unclassified failure here, which reads as a store that may still be
        // holding the secret and blocks deleting the account it belongs to.
        None if is_dead_session_bus(err) => SecretsError::NoBackend,
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
            // A miss is not yet an absence on the Secret Service: the store reads by searching the
            // service and writes by resolving the default collection, so a provider that has never
            // been initialized answers "nothing found" to every read and refuses every write. The
            // round trip that separates the two is paid only when nothing was found.
            Err(keyring_core::Error::NoEntry) => {
                #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
                if crate::probe::no_default_collection() {
                    return Err(SecretsError::NoCollection);
                }
                Ok(None)
            }
            // `get_secret` rather than `get_password`: the string reader is the one call that can
            // hand back an error carrying the raw secret when the stored bytes are not UTF-8.
            Err(err) => Err(map_error(&err, "read")),
        }
    }

    fn set(&self, account: Uuid, kind: SecretKind, value: Secret) -> Result<(), SecretsError> {
        crate::store::refuse_empty(&value)?;
        entry_for(account, kind)?
            .set_secret(value.expose())
            .map_err(|err| map_error(&err, "store"))
    }

    fn delete(&self, account: Uuid, kind: SecretKind) -> Result<(), SecretsError> {
        match entry_for(account, kind)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
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
        // Both of the variants that hand the stored bytes back out. `BadDataFormat` renders them
        // through the derived `Debug` of the vector it carries, and it is reachable from a store
        // that transforms what it holds, which the Secret Service one does.
        let leaky = [
            keyring_core::Error::BadEncoding(b"hunter2".to_vec()),
            keyring_core::Error::BadDataFormat(
                b"hunter2".to_vec(),
                Box::new(std::io::Error::other("short read")),
            ),
        ];
        for err in leaky {
            let mapped = map_error(&err, "read");
            let rendered = format!("{mapped} {mapped:?}");
            assert!(!rendered.contains("hunter2"), "{rendered}");
            assert!(matches!(mapped, SecretsError::Backend { step: "read" }));
        }
    }

    #[test]
    fn several_matching_items_are_their_own_condition() {
        let err = keyring_core::Error::Ambiguous(Vec::new());
        assert!(matches!(map_error(&err, "read"), SecretsError::Ambiguous));
    }

    /// The store API's enum is non-exhaustive and five of its variants are unreachable with the keys
    /// and the binary API used here, so they all land on the catch-all rather than on a guess.
    /// `NoDefaultStore` is among them because entries are built from an owned store rather than the
    /// process-wide default, so the condition it reports cannot arise; it is asserted rather than
    /// assumed, because a later edit reaching for `Entry::new` would make it the answer to every
    /// call and it would read as an ordinary backend failure.
    #[test]
    fn unreachable_variants_land_on_the_catch_all() {
        let cases = [
            keyring_core::Error::TooLong("user".to_owned(), 512),
            keyring_core::Error::Invalid("service".to_owned(), "empty".to_owned()),
            keyring_core::Error::NoEntry,
            keyring_core::Error::NoDefaultStore,
            keyring_core::Error::NotSupportedByStore("search".to_owned()),
            keyring_core::Error::BadStoreFormat("truncated".to_owned()),
        ];
        for err in cases {
            assert!(matches!(
                map_error(&err, "store"),
                SecretsError::Backend { step: "store" }
            ));
        }
    }

    /// A platform failure this crate can read no status out of stays a backend failure rather than
    /// being guessed at as a lock: the Credential Manager has no lock to report, and on a keychain
    /// it would send a user off to unlock a store that is already open.
    #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
    #[test]
    fn a_platform_failure_with_no_readable_status_stays_a_backend_failure() {
        let err =
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("something")));
        assert!(matches!(
            map_error(&err, "read"),
            SecretsError::Backend { step: "read" }
        ));
    }

    /// The store path's half of the lock classification: the same three codes, through the same
    /// downcast, arriving as the condition a caller retries after an unlock instead of as an opaque
    /// failure. Compiled by the Apple cross-check job and run by nothing here.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_shut_keychain_maps_to_locked() {
        for code in [-25308, -25293, -128] {
            let err = keyring_core::Error::PlatformFailure(Box::new(
                security_framework::base::Error::from_code(code),
            ));
            assert!(
                matches!(map_error(&err, "read"), SecretsError::Locked),
                "{code}"
            );
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
                let outer = keyring_core::Error::NoStorageAccess(boxed(err));
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
                keyring_core::Error::NoStorageAccess(boxed(secret_service::Error::NoResult)),
                keyring_core::Error::PlatformFailure(boxed(secret_service::Error::NoResult)),
            ] {
                assert!(matches!(
                    map_error(&outer, "store"),
                    SecretsError::NoCollection
                ));
            }
        }

        #[test]
        fn no_bus_or_no_provider_maps_to_no_backend() {
            let outer =
                keyring_core::Error::PlatformFailure(boxed(secret_service::Error::Unavailable));
            assert!(matches!(map_error(&outer, "read"), SecretsError::NoBackend));

            let unknown = secret_service::Error::ZbusFdo(zbus::fdo::Error::ServiceUnknown(
                "org.freedesktop.secrets".to_owned(),
            ));
            let outer = keyring_core::Error::PlatformFailure(boxed(unknown));
            assert!(matches!(map_error(&outer, "read"), SecretsError::NoBackend));
        }

        /// The store path's half of the dead-bus classification, which the probe path has always
        /// answered. A socket that is there and refuses is no store, and while this path left it
        /// unclassified the same session reported storage as unavailable and then refused to delete
        /// the account, because an unclassified failure is read as a store that may still be holding
        /// the secret. It arrives under both of keyring's wrappers depending on which call reached
        /// it, and on every verb, so the step is the one a sweep uses.
        #[test]
        fn a_socket_that_will_not_take_a_connection_maps_to_no_backend() {
            for kind in [
                std::io::ErrorKind::NotFound,
                std::io::ErrorKind::ConnectionRefused,
                std::io::ErrorKind::PermissionDenied,
            ] {
                let dead = || {
                    secret_service::Error::Zbus(zbus::Error::InputOutput(std::sync::Arc::new(
                        std::io::Error::new(kind, "socket"),
                    )))
                };
                for outer in [
                    keyring_core::Error::NoStorageAccess(boxed(dead())),
                    keyring_core::Error::PlatformFailure(boxed(dead())),
                ] {
                    assert!(
                        matches!(map_error(&outer, "delete"), SecretsError::NoBackend),
                        "{kind:?}"
                    );
                }
            }

            // Anything else on that socket is still an unclassified failure rather than a guess.
            let broken =
                secret_service::Error::Zbus(zbus::Error::InputOutput(std::sync::Arc::new(
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "socket"),
                )));
            assert!(matches!(
                map_error(
                    &keyring_core::Error::PlatformFailure(boxed(broken)),
                    "delete"
                ),
                SecretsError::Backend { step: "delete" }
            ));
        }

        /// A sandbox bus policy refusing the name is a different answer from the name not being
        /// there: one is fixed by a permission, the other by installing a keyring.
        #[test]
        fn a_refused_name_maps_to_denied() {
            let denied = secret_service::Error::ZbusFdo(zbus::fdo::Error::AccessDenied(
                "not allowed".to_owned(),
            ));
            let outer = keyring_core::Error::PlatformFailure(boxed(denied));
            assert!(matches!(map_error(&outer, "read"), SecretsError::Denied));
        }

        /// Keyring boxes the Secret Service error, and the downcast that reads it is silent when it
        /// fails. A source of another type must fall to the catch-all rather than be misread.
        #[test]
        fn an_unrecognized_source_falls_to_the_catch_all() {
            let outer =
                keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("other")));
            assert!(matches!(
                map_error(&outer, "read"),
                SecretsError::Backend { step: "read" }
            ));
        }
    }
}
