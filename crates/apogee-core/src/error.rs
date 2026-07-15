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
    #[error("secrets: {0}")]
    Secrets(#[from] apogee_secrets::SecretsError),
    #[error("otp: {0}")]
    Otp(#[from] apogee_otp::OtpError),
    #[error("no profile with id {0}")]
    NoProfile(Uuid),
    #[error("import from {path:?} failed: {detail}")]
    Import { path: PathBuf, detail: String },
    #[error("initialization failed: {detail}")]
    Init { detail: String },
}
