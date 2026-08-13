// `deny` rather than the `forbid` every other crate root here carries, for one carve-out taken where
// it is named: `encrypted_file::disk`'s Windows arm has to reach advapi32 to put an owner-only
// access list on the fallback store's directory. The standard library exposes no security-descriptor
// API, and on Windows that descriptor is the whole of what a mode is on the other platforms.
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
//! OS keyring-backed storage for account secrets.
//!
//! One [`SecretStore`] seam over the platform credential stores: the freedesktop Secret Service on
//! Linux (GNOME Keyring, KWallet, KeePassXC), the Credential Manager on Windows, the Keychain on
//! macOS and iOS. Secrets are addressed by account UUID and [`SecretKind`], so they are shared by
//! every profile that signs in as that account, and they travel in a [`Secret`] that zeroizes on
//! drop and implements no trait that could print or serialize it.
//!
//! [`SecretStore::probe`] reports which store answered and what condition it is in without reading a
//! stored secret, writing, or raising an unlock prompt, so a caller can tell a locked keyring from a
//! sandbox that cannot reach one, and say something useful instead of failing blind.
//!
//! # Layout
//!
//! - [`SecretStore`] is the trait every backend implements; [`Secrets`] is the handle a composition
//!   root holds, wrapping whichever backend it was given.
//! - [`OsKeyring`] is the default backend, dispatching to the Secret Service, Credential Manager, or
//!   Keychain for the host platform.
//! - [`EncryptedFile`] is the opt-in passphrase-sealed fallback for a session with no platform
//!   keyring, gated by a [`Passphrase`] and a [`Consent`] token.
//! - [`Null`] is the backend for an account whose secrets are never written down.
//! - [`BackendReport`] is what [`SecretStore::probe`] returns: a [`Backend`], a [`BackendState`],
//!   and an optional [`Sandbox`].
//! - [`Import`] reads another launcher's stored credential so a user does not have to retype it.
//! - [`SecretsError`] is the shared error taxonomy every backend answers through.
//!
//! # What the platform store does and does not buy
//!
//! At rest it encrypts the item, keeps it out of other user accounts, and gates it on the OS
//! session. It does **not** defend against code running as the same user in an unlocked session: the
//! Secret Service has no per-application access rules and the Credential Manager is per-user.
//! Zeroize-on-drop narrows the window a secret sits in this process's memory; it cannot erase copies
//! made before the value reached [`Secret`], and it does not pin pages.
//!
//! # Blocking
//!
//! Every [`SecretStore`] call blocks and may raise the platform's unlock prompt. On Linux the D-Bus
//! client panics when it is driven from inside an async runtime's worker, so a caller on a runtime
//! must wrap these calls in `tokio::task::spawn_blocking`.
//!
//! # Examples
//!
//! [`Null`] never touches a real keyring, so it is safe to run here: a caller wires up
//! [`Secrets`] around whichever backend the composition root chose, and every subsystem downstream
//! reads it through the same [`SecretStore`] trait object.
//!
//! ```
//! use std::sync::Arc;
//!
//! use apogee_secrets::{Null, SecretKind, SecretStore, Secrets};
//! use uuid::Uuid;
//!
//! let secrets = Secrets::with_backend(Arc::new(Null::new()));
//! assert!(!secrets.store().probe().is_usable());
//! assert!(secrets.store().get(Uuid::nil(), SecretKind::Password)?.is_none());
//! # Ok::<(), apogee_secrets::SecretsError>(())
//! ```

// The Secret Service session has to negotiate the Diffie-Hellman-agreed AES transport, or secret
// payloads cross the session bus in the clear. Cargo does not surface a dependency's features as a
// cfg, so the passthrough feature declared in Cargo.toml is what gives this check something to test.
#[cfg(all(
    any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"),
    not(feature = "encrypted-session")
))]
compile_error!(
    "the Secret Service session must negotiate the Diffie-Hellman AES transport; the \
     `encrypted-session` feature (on by default) is off, which would send secret payloads across \
     the session bus in cleartext"
);

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios",
)))]
compile_error!("apogee-secrets has no credential store for this target");

mod encrypted_file;
mod error;
mod import;
mod keyring_store;
mod null;
mod report;
mod secret;
mod store;

#[cfg(feature = "mock")]
mod memory;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
mod probe;
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
mod probe_native;

// The Keychain status table and the reader for it. Compiled on macOS/iOS because the Keychain
// backend needs it, on Windows because `keyring_store.rs`'s Credential Manager arm calls
// `apple::locked` too (a permanent no-op there, since the Credential Manager raises no status of
// this shape), and additionally under `cfg(test)` on Linux/BSD, so the table runs in the ordinary
// test job: no job in this repository has Apple hardware, and a table only Apple could execute is a
// table nothing holds.
#[cfg(any(
    test,
    not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))
))]
mod apple;

pub use encrypted_file::{Consent, EncryptedFile, FileState, KdfCost, Passphrase, Unprompted};
pub use error::SecretsError;
pub use import::{ForeignCredentialStore, ForeignKey, ForeignSecretsFile, Import, ImportSource};
pub use keyring_store::OsKeyring;
pub use null::Null;
pub use report::{Backend, BackendReport, BackendState, Sandbox};
pub use secret::{Secret, SecretKind};
pub use store::{SecretStore, Secrets};

#[cfg(feature = "mock")]
pub use memory::{Call, FailAt, MemoryStore};

/// Parse arbitrary bytes as the fallback store's file header, for the fuzz workspace.
///
/// Each of these takes what a fuzzer produces, which is what the file's own parser takes off a disk.
/// They are behind a feature no shipping build enables, so a decoder fed hostile input never becomes
/// part of this crate's API.
#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_frame(bytes: &[u8]) {
    encrypted_file::parse_frame(bytes);
}

/// Parse arbitrary bytes as the fallback store's record table. As [`fuzz_parse_frame`].
#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_records(bytes: &[u8]) {
    encrypted_file::parse_records(bytes);
}

/// Parse arbitrary bytes as the table another launcher exports its passwords into, looking for
/// `wanted`. As [`fuzz_parse_frame`], with two differences.
///
/// The bytes are cleartext rather than sealed, and nothing authenticates them before the decoder is
/// handed them: the file sits on a path this launcher does not own, so its contents are a stranger's
/// to choose rather than only the decoder's own totality.
///
/// And it answers a property rather than only declining to abort. `false` means the decode returned
/// a password longer than the bytes it was decoded from, which no amount of JSON escaping can do.
#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_exported_file(bytes: &[u8], wanted: &str) -> bool {
    import::fuzz_exported_password(bytes, wanted)
}
