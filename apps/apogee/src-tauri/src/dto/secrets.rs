//! Credential-backend health without any secret-presence surface.

use apogee_core::{Backend, BackendReport, BackendState, FileState, KdfCost, Sandbox, Secret};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use zeroize::Zeroizing;

use super::path::PathDto;

/// Bytes that arrived over IPC and are erased when the request leaves scope.
///
/// `Zeroizing` owns deserialization, so the allocation becomes guarded as it is constructed. The
/// buffer is moved into core's `Secret` without making a second copy. It deliberately implements no
/// outbound serialization, debug rendering, or cloning.
#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub(crate) fn into_secret(mut self) -> Secret {
        Secret::new(std::mem::take(&mut *self.0))
    }

    #[cfg(test)]
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// The sealed file's complete display-safe lifecycle reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SecretsFileStatus.ts")]
pub(crate) struct SecretsFileStatusDto {
    state: SecretsFileStateDto,
    is_open: bool,
}

impl SecretsFileStatusDto {
    pub(crate) fn new(state: FileState, is_open: bool) -> Self {
        Self {
            state: SecretsFileStateDto::from(state),
            is_open,
        }
    }
}

/// A header-only sealed-file state, without a filesystem capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum SecretsFileStateDto {
    Absent,
    Sealed { work: KdfCostDto },
    Unreadable,
    Foreign,
    Unknown,
}

impl From<FileState> for SecretsFileStateDto {
    fn from(state: FileState) -> Self {
        match state {
            FileState::Absent => Self::Absent,
            FileState::Sealed { work } => Self::Sealed {
                work: KdfCostDto::from(work),
            },
            FileState::Unreadable => Self::Unreadable,
            FileState::Foreign => Self::Foreign,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KdfCostDto {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

impl From<KdfCost> for KdfCostDto {
    fn from(cost: KdfCost) -> Self {
        Self {
            memory_kib: cost.memory_kib(),
            passes: cost.passes(),
            lanes: cost.lanes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SecretsFileRemoval.ts")]
pub(crate) struct SecretsFileRemovalDto {
    removed: bool,
    file: SecretsFileStatusDto,
}

impl SecretsFileRemovalDto {
    pub(crate) fn new(removed: bool, file: SecretsFileStatusDto) -> Self {
        Self { removed, file }
    }
}

/// Explicit confirmation and the new store's one-way passphrase.
#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "CreateSecretsFileRequest.ts")]
pub(crate) struct CreateSecretsFileRequestDto {
    confirmed: bool,
    #[ts(type = "number[]")]
    passphrase: SecretBytes,
}

impl CreateSecretsFileRequestDto {
    pub(crate) fn into_parts(self) -> (bool, Secret) {
        (self.confirmed, self.passphrase.into_secret())
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "ChangeSecretsFilePassphraseRequest.ts")]
pub(crate) struct ChangeSecretsFilePassphraseRequestDto {
    #[ts(type = "number[]")]
    current: SecretBytes,
    #[ts(type = "number[]")]
    replacement: SecretBytes,
}

impl ChangeSecretsFilePassphraseRequestDto {
    pub(crate) fn into_parts(self) -> (Secret, Secret) {
        (self.current.into_secret(), self.replacement.into_secret())
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "RemoveSecretsFileRequest.ts")]
pub(crate) struct RemoveSecretsFileRequestDto {
    confirmed: bool,
}

impl RemoveSecretsFileRequestDto {
    pub(crate) const fn confirmed(&self) -> bool {
        self.confirmed
    }
}

#[derive(Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(export, export_to = "PassphraseAnswer.ts")]
pub(crate) enum PassphraseAnswerDto {
    Submit {
        #[ts(type = "number[]")]
        passphrase: SecretBytes,
    },
    Cancel,
}

impl PassphraseAnswerDto {
    pub(crate) fn into_secret(self) -> Option<Secret> {
        match self {
            Self::Submit { passphrase } => Some(passphrase.into_secret()),
            Self::Cancel => None,
        }
    }
}

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

    #[test]
    fn every_sealed_file_state_has_a_display_safe_projection() {
        let states = [
            (
                FileState::Absent,
                r#"{"state":{"kind":"absent"},"isOpen":false}"#,
            ),
            (
                FileState::Sealed {
                    work: KdfCost::floor(),
                },
                r#"{"state":{"kind":"sealed","work":{"memoryKib":19456,"passes":2,"lanes":1}},"isOpen":true}"#,
            ),
            (
                FileState::Unreadable,
                r#"{"state":{"kind":"unreadable"},"isOpen":false}"#,
            ),
            (
                FileState::Foreign,
                r#"{"state":{"kind":"foreign"},"isOpen":false}"#,
            ),
        ];

        for (state, expected) in states {
            let is_open = matches!(state, FileState::Sealed { .. });
            let json = serde_json::to_string(&SecretsFileStatusDto::new(state, is_open))
                .unwrap_or_default();
            assert_eq!(json, expected);
            assert!(!json.contains("path"));
            assert!(!json.contains("passphrase"));
        }
    }

    #[test]
    fn inbound_secret_bytes_move_into_the_domain_secret() {
        let secret = SecretBytes::new(b"one-way".to_vec()).into_secret();
        assert_eq!(secret.expose(), b"one-way");
    }
}
