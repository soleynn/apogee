//! The launcher core's aggregate error type.
//!
//! Every subsystem keeps its own typed failures; the core wraps each so a shell receives one
//! exhaustive enum and can always tell which layer failed. No variant carries user-facing prose:
//! the shell maps a variant to a localized message.

use std::path::PathBuf;

use thiserror::Error;
use uuid::Uuid;

use crate::store::StoreError;

/// Anything the core can fail with, aggregated from every subsystem.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("protocol: {0}")]
    Proto(#[from] sqex_proto::ProtoError),
    #[error("download: {0}")]
    Fetch(#[from] apogee_fetch::FetchError),
    #[error("patch: {0}")]
    Patch(#[from] apogee_patcher::PatchError),
    #[error("runtime: {0}")]
    Runtime(#[from] apogee_runtime::RuntimeError),
    #[error("addons: {0}")]
    Addons(#[from] apogee_addons::AddonError),
    #[error("companion tool {program:?} failed: {reason}")]
    Addon { program: PathBuf, reason: String },
    #[error("{var} could not be resolved: {reason}")]
    Config { var: String, reason: &'static str },
    #[error("secrets: {0}")]
    Secrets(#[from] apogee_secrets::SecretsError),
    #[error("otp: {0}")]
    Otp(#[from] apogee_otp::OtpError),
    /// Obfuscating the Steam authentication ticket failed. The launch-argument half of that crate
    /// cannot fail, so this only ever comes from the ticket.
    #[error("authentication ticket: {0}")]
    Crypto(#[from] sqex_crypto::CryptoError),
    /// A Steam service account was asked to log in on a build that cannot reach a Steam client. The
    /// account is fine; this launcher has no way to mint the ticket it needs.
    #[error("this build cannot obtain a Steam authentication ticket")]
    NoSteam,
    /// The host exposes no clock the game will re-derive its launch-argument key from. The game reads
    /// `GetTickCount`, which Wine maps onto the host `CLOCK_MONOTONIC_RAW`; where the game is not a
    /// Wine process, no host clock is known to match it.
    #[error("this host has no tick source the game can re-derive its launch key from")]
    NoTickSource,
    #[error("no profile with id {0}")]
    NoProfile(Uuid),
    #[error("no account with id {0}")]
    NoAccount(Uuid),
    #[error("the account password is not valid text")]
    InvalidCredential,
    #[error("import from {path:?} failed: {detail}")]
    Import { path: PathBuf, detail: String },
    #[error("initialization failed: {detail}")]
    Init { detail: String },
    #[error("preparing the launch failed: {detail}")]
    Launch { detail: String },
    #[error("the patch flow could not bring the install current: {detail}")]
    PatchIncomplete { detail: String },
    #[error("preparing the repair failed: {detail}")]
    Repair { detail: String },
}
