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
    /// Some of the components asked for did not install. A count rather than the reasons: each one is
    /// already on the event stream as the event that failed it, and repeating them here makes one problem
    /// look like two. This exists so a shell can tell that what it asked for did not entirely happen.
    #[error("{failed} of {total} components could not be installed")]
    Components { failed: usize, total: usize },
}
