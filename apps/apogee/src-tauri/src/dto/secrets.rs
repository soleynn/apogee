//! Credential-backend health without any secret-presence surface.

use apogee_core::{Backend, BackendReport, BackendState, Sandbox};
use serde::Serialize;
use ts_rs::TS;

use super::path::PathDto;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SecretsReport.ts")]
pub(crate) struct SecretsReportDto {
    backend: BackendDto,
    state: BackendStateDto,
    sandbox: Option<SandboxDto>,
    secrets_path: PathDto,
}

impl SecretsReportDto {
    pub(crate) fn new(report: &BackendReport, secrets_path: &std::path::Path) -> Self {
        Self {
            backend: BackendDto::from(report.backend),
            state: BackendStateDto::from(report.state),
            sandbox: report.sandbox.as_ref().map(SandboxDto::from),
            secrets_path: PathDto::from(secrets_path),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum BackendDto {
    SecretService,
    WindowsCredentialManager,
    AppleKeychain,
    EncryptedFile,
    Null,
    Memory,
    Unknown,
}

impl From<Backend> for BackendDto {
    fn from(backend: Backend) -> Self {
        match backend {
            Backend::SecretService => Self::SecretService,
            Backend::WindowsCredentialManager => Self::WindowsCredentialManager,
            Backend::AppleKeychain => Self::AppleKeychain,
            Backend::EncryptedFile => Self::EncryptedFile,
            Backend::Null => Self::Null,
            Backend::Memory => Self::Memory,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum BackendStateDto {
    Ready,
    Locked,
    NoDefaultCollection,
    NoSessionBus,
    NoProvider,
    SandboxDenied,
    NotStoring,
    Unreachable,
    Unknown,
}

impl From<BackendState> for BackendStateDto {
    fn from(state: BackendState) -> Self {
        match state {
            BackendState::Ready => Self::Ready,
            BackendState::Locked => Self::Locked,
            BackendState::NoDefaultCollection => Self::NoDefaultCollection,
            BackendState::NoSessionBus => Self::NoSessionBus,
            BackendState::NoProvider => Self::NoProvider,
            BackendState::SandboxDenied => Self::SandboxDenied,
            BackendState::NotStoring => Self::NotStoring,
            BackendState::Unreachable => Self::Unreachable,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum SandboxDto {
    Flatpak {
        app_id: Option<String>,
        bus_filtered: bool,
    },
    Container,
    Unknown,
}

impl From<&Sandbox> for SandboxDto {
    fn from(sandbox: &Sandbox) -> Self {
        match sandbox {
            Sandbox::Flatpak {
                app_id,
                bus_filtered,
            } => Self::Flatpak {
                app_id: app_id.clone(),
                bus_filtered: *bus_filtered,
            },
            Sandbox::Container => Self::Container,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_contains_health_but_no_presence_claim() {
        let report = BackendReport::new(Backend::Null, BackendState::NotStoring);
        let json = serde_json::to_string(&SecretsReportDto::new(
            &report,
            std::path::Path::new("secrets.bin"),
        ))
        .unwrap_or_default();

        assert!(json.contains(r#""backend":"null""#));
        assert!(json.contains(r#""state":"notStoring""#));
        assert!(!json.contains("password"));
        assert!(!json.contains("present"));
    }
}
