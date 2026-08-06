#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
//! OS keyring-backed storage for account secrets.
//!
//! One [`SecretStore`] seam over the platform credential stores: the freedesktop Secret Service on
//! Linux (GNOME Keyring, KWallet, KeePassXC), the Credential Manager on Windows, the Keychain on
//! macOS. Secrets are addressed by account UUID and [`SecretKind`], so they are shared by every
//! profile that signs in as that account, and they travel in a [`Secret`] that zeroizes on drop and
//! implements no trait that could print or serialize it.
//!
//! [`SecretStore::probe`] reports which store answered and what condition it is in without reading,
//! writing, or raising an unlock prompt, so a caller can tell a locked keyring from a sandbox that
//! cannot reach one, and say something useful instead of failing blind.
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

pub use encrypted_file::{Consent, EncryptedFile, FileState, KdfCost, Passphrase, Unprompted};
pub use error::SecretsError;
pub use import::{
    FOREIGN_SCHEMA, ForeignCredentialStore, ForeignKey, ForeignSecretsFile, ImportSource,
};
pub use keyring_store::OsKeyring;
pub use null::Null;
pub use report::{Backend, BackendReport, BackendState, Sandbox};
pub use secret::{Secret, SecretKind};
pub use store::{SecretStore, Secrets};

#[cfg(feature = "mock")]
pub use memory::{Call, FailAt, MemoryStore};

/// Parse arbitrary bytes as the fallback store's file header, for the fuzz workspace.
///
/// Both of these take what a fuzzer produces, which is what the file's own parser takes off a disk.
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
