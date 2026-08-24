//! Explicitly selected error fields safe to send to the webview.

use apogee_core::{CoreError, StoreError};
use serde::Serialize;
use ts_rs::TS;

use super::path::PathDto;

/// The aggregate error kind without `Display` text or nested protocol excerpts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum CoreErrorDto {
    Store {
        store: StoreErrorDto,
    },
    Proto,
    Fetch,
    Patch,
    GameRunning {
        executable: Option<String>,
        pid: Option<u32>,
    },
    Runtime,
    Addons,
    Addon,
    Config {
        variable: String,
        reason: &'static str,
    },
    Secrets,
    Otp,
    Crypto,
    NoSteam,
    NoTickSource,
    NoProfile {
        profile: String,
    },
    NoAccount {
        account: String,
    },
    InvalidCredential,
    Import,
    XivImport,
    Support,
    FirstRun,
    Init,
    Launch,
    PatchIncomplete,
    Repair,
    FrontierLink {
        id: String,
    },
    Unavailable {
        command: &'static str,
    },
    Unknown,
}

impl From<&CoreError> for CoreErrorDto {
    fn from(error: &CoreError) -> Self {
        match error {
            CoreError::Store(store) => Self::Store {
                store: StoreErrorDto::from(store),
            },
            CoreError::Proto(_) => Self::Proto,
            CoreError::Fetch(_) => Self::Fetch,
            CoreError::Patch(_) => Self::Patch,
            CoreError::GameRunning { process } => Self::GameRunning {
                executable: process.as_ref().map(|process| process.executable.clone()),
                pid: process.as_ref().map(|process| process.pid),
            },
            CoreError::Runtime(_) => Self::Runtime,
            CoreError::Addons(_) => Self::Addons,
            CoreError::Addon { .. } => Self::Addon,
            CoreError::Config { var, reason } => Self::Config {
                variable: var.clone(),
                reason,
            },
            CoreError::Secrets(_) => Self::Secrets,
            CoreError::Otp(_) => Self::Otp,
            CoreError::Crypto(_) => Self::Crypto,
            CoreError::NoSteam => Self::NoSteam,
            CoreError::NoTickSource => Self::NoTickSource,
            CoreError::NoProfile(profile) => Self::NoProfile {
                profile: profile.to_string(),
            },
            CoreError::NoAccount(account) => Self::NoAccount {
                account: account.to_string(),
            },
            CoreError::InvalidCredential => Self::InvalidCredential,
            CoreError::Import { .. } => Self::Import,
            CoreError::XivImport(_) => Self::XivImport,
            CoreError::Support(_) => Self::Support,
            CoreError::FirstRun(_) => Self::FirstRun,
            CoreError::Init { .. } => Self::Init,
            CoreError::Launch { .. } => Self::Launch,
            CoreError::PatchIncomplete { .. } => Self::PatchIncomplete,
            CoreError::Repair { .. } => Self::Repair,
            CoreError::FrontierLink { id } => Self::FrontierLink { id: id.clone() },
            CoreError::Unavailable { command } => Self::Unavailable { command },
            _ => Self::Unknown,
        }
    }
}

/// Store failures need their paths for recovery, but never serialize the source error implicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum StoreErrorDto {
    Corrupt { path: PathDto, backup: PathDto },
    Io { path: PathDto },
    NotFound { path: PathDto },
    Unknown,
}

impl From<&StoreError> for StoreErrorDto {
    fn from(error: &StoreError) -> Self {
        match error {
            StoreError::Corrupt {
                path,
                backup,
                detail: _,
            } => Self::Corrupt {
                path: PathDto::from(path.as_path()),
                backup: PathDto::from(backup.as_path()),
            },
            StoreError::Io { path, .. } => Self::Io {
                path: PathDto::from(path.as_path()),
            },
            StoreError::NotFound { path } => Self::NotFound {
                path: PathDto::from(path.as_path()),
            },
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_error_details_do_not_cross_the_boundary() {
        let error = CoreError::Launch {
            detail: "token=planted-secret".to_owned(),
        };
        let json = serde_json::to_string(&CoreErrorDto::from(&error)).unwrap_or_default();

        assert!(!json.is_empty());
        assert_eq!(json, r#"{"kind":"launch"}"#);
        assert!(!json.contains("planted-secret"));
    }

    #[test]
    fn corrupt_store_details_do_not_cross_the_boundary() {
        let error = CoreError::Store(StoreError::Corrupt {
            path: "profiles.json".into(),
            backup: "profiles.json.corrupt".into(),
            detail: "unexpected value token=planted-secret".to_owned(),
        });
        let json = serde_json::to_string(&CoreErrorDto::from(&error)).unwrap_or_default();

        assert!(json.contains(r#""kind":"corrupt""#));
        assert!(json.contains(r#""display":"profiles.json""#));
        assert!(json.contains(r#""display":"profiles.json.corrupt""#));
        assert!(!json.contains("planted-secret"));
    }
}
