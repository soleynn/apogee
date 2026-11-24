//! Read-only core projections exposed as direct shell methods.

use apogee_core::{
    BundlePart, CatalogViewEntry, NextAction, NextCommand, NextVerb, PendingReading, Provenance,
    ResolvedSetup, SetupValue, SyncStatus,
};
use serde::Serialize;
use ts_rs::TS;

use super::store::GpuSelectDto;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "NextAction.ts")]
pub(crate) struct NextActionDto {
    verb: NextVerbDto,
    command: NextCommandDto,
    pending: Option<PendingReadingDto>,
    resumable: bool,
    blocked: Option<String>,
    patching_available: bool,
}

impl From<&NextAction> for NextActionDto {
    fn from(action: &NextAction) -> Self {
        Self {
            verb: NextVerbDto::from(action.verb),
            command: NextCommandDto::from(action.command),
            pending: action.pending.map(PendingReadingDto::from),
            resumable: action.resumable,
            blocked: action.blocked.clone(),
            patching_available: action.patching_available,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum NextVerbDto {
    Play,
    UpdateAndPlay,
    Install,
    Resume,
    Repair,
    SignIn,
    AcceptTerms,
    WaitForMaintenance,
    CloseGameFirst,
    Unknown,
}

impl From<NextVerb> for NextVerbDto {
    fn from(verb: NextVerb) -> Self {
        match verb {
            NextVerb::Play => Self::Play,
            NextVerb::UpdateAndPlay => Self::UpdateAndPlay,
            NextVerb::Install => Self::Install,
            NextVerb::Resume => Self::Resume,
            NextVerb::Repair => Self::Repair,
            NextVerb::SignIn => Self::SignIn,
            NextVerb::AcceptTerms => Self::AcceptTerms,
            NextVerb::WaitForMaintenance => Self::WaitForMaintenance,
            NextVerb::CloseGameFirst => Self::CloseGameFirst,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum NextCommandDto {
    Launch,
    PatchAndPlay,
    Install,
    Repair,
    Login,
    WaitForGate,
    Unknown,
}

impl From<NextCommand> for NextCommandDto {
    fn from(command: NextCommand) -> Self {
        match command {
            NextCommand::Launch => Self::Launch,
            NextCommand::PatchAndPlay => Self::PatchAndPlay,
            NextCommand::Install => Self::Install,
            NextCommand::Repair => Self::Repair,
            NextCommand::Login => Self::Login,
            NextCommand::WaitForGate => Self::WaitForGate,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
struct PendingReadingDto {
    count: u32,
    bytes: u64,
    as_of: u64,
}

impl From<PendingReading> for PendingReadingDto {
    fn from(reading: PendingReading) -> Self {
        Self {
            count: reading.count,
            bytes: reading.bytes,
            as_of: reading.as_of,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "CatalogEntry.ts")]
pub(crate) struct CatalogEntryDto {
    name: String,
    version: String,
    installed: bool,
    available: bool,
    size: Option<u64>,
    recommended: bool,
}

impl From<&CatalogViewEntry> for CatalogEntryDto {
    fn from(entry: &CatalogViewEntry) -> Self {
        Self {
            name: entry.name.clone(),
            version: entry.version.clone(),
            installed: entry.installed,
            available: entry.available,
            size: entry.size,
            recommended: entry.recommended,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "ResolvedSetup.ts")]
pub(crate) struct ResolvedSetupDto {
    value: SetupValueDto,
    source: ProvenanceDto,
}

impl From<&ResolvedSetup> for ResolvedSetupDto {
    fn from(setup: &ResolvedSetup) -> Self {
        Self {
            value: SetupValueDto::from(&setup.value),
            source: ProvenanceDto::from(setup.source),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum SetupValueDto {
    Runner {
        name: String,
        version: Option<String>,
    },
    Sync {
        status: SyncStatusDto,
    },
    Gpu {
        selection: GpuSelectDto,
        identity: Option<String>,
    },
    Dxvk {
        version: Option<String>,
        nvapi: bool,
    },
    Dalamud {
        enabled: bool,
    },
    Unknown,
}

impl From<&SetupValue> for SetupValueDto {
    fn from(value: &SetupValue) -> Self {
        match value {
            SetupValue::Runner { name, version } => Self::Runner {
                name: name.clone(),
                version: version.clone(),
            },
            SetupValue::Sync(status) => Self::Sync {
                status: SyncStatusDto::from(*status),
            },
            SetupValue::Gpu {
                selection,
                identity,
            } => Self::Gpu {
                selection: GpuSelectDto::from(selection),
                identity: identity.clone(),
            },
            SetupValue::Dxvk { version, nvapi } => Self::Dxvk {
                version: version.clone(),
                nvapi: *nvapi,
            },
            SetupValue::Dalamud { enabled } => Self::Dalamud { enabled: *enabled },
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum SyncStatusDto {
    Ntsync,
    Fsync,
    Esync,
    None,
}

impl From<SyncStatus> for SyncStatusDto {
    fn from(status: SyncStatus) -> Self {
        match status {
            SyncStatus::Ntsync => Self::Ntsync,
            SyncStatus::Fsync => Self::Fsync,
            SyncStatus::Esync => Self::Esync,
            SyncStatus::None => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum ProvenanceDto {
    Profile,
    Host,
    Catalog,
    Prefix,
    Default,
    Unknown,
}

impl From<Provenance> for ProvenanceDto {
    fn from(source: Provenance) -> Self {
        match source {
            Provenance::Profile => Self::Profile,
            Provenance::Host => Self::Host,
            Provenance::Catalog => Self::Catalog,
            Provenance::Prefix => Self::Prefix,
            Provenance::Default => Self::Default,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "BundlePart.ts")]
pub(crate) enum BundlePartDto {
    SystemReport,
    RecentLogs,
    Profiles,
    Settings,
    ShellFacts,
    Unknown,
}

impl From<BundlePart> for BundlePartDto {
    fn from(part: BundlePart) -> Self {
        match part {
            BundlePart::SystemReport => Self::SystemReport,
            BundlePart::RecentLogs => Self::RecentLogs,
            BundlePart::Profiles => Self::Profiles,
            BundlePart::Settings => Self::Settings,
            BundlePart::ShellFacts => Self::ShellFacts,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_action_keeps_every_decision_field() {
        let action = NextAction {
            verb: NextVerb::Resume,
            command: NextCommand::PatchAndPlay,
            pending: Some(PendingReading {
                count: 7,
                bytes: 42,
                as_of: 11,
            }),
            resumable: true,
            blocked: Some("state-no-service".to_owned()),
            patching_available: false,
        };

        let json = serde_json::to_string(&NextActionDto::from(&action)).unwrap_or_default();
        assert_eq!(
            json,
            r#"{"verb":"resume","command":"patchAndPlay","pending":{"count":7,"bytes":42,"asOf":11},"resumable":true,"blocked":"state-no-service","patchingAvailable":false}"#
        );
    }

    #[test]
    fn resolved_setup_keeps_value_and_provenance() {
        let cases = [
            (
                ResolvedSetup {
                    value: SetupValue::Runner {
                        name: "wine".to_owned(),
                        version: Some("1".to_owned()),
                    },
                    source: Provenance::Catalog,
                },
                r#"{"value":{"kind":"runner","name":"wine","version":"1"},"source":"catalog"}"#,
            ),
            (
                ResolvedSetup {
                    value: SetupValue::Sync(SyncStatus::Ntsync),
                    source: Provenance::Host,
                },
                r#"{"value":{"kind":"sync","status":"ntsync"},"source":"host"}"#,
            ),
            (
                ResolvedSetup {
                    value: SetupValue::Gpu {
                        selection: apogee_core::GpuSelect::VulkanDevice("10de:2482".to_owned()),
                        identity: Some("Discrete GPU".to_owned()),
                    },
                    source: Provenance::Profile,
                },
                r#"{"value":{"kind":"gpu","selection":{"kind":"vulkanDevice","value":"10de:2482"},"identity":"Discrete GPU"},"source":"profile"}"#,
            ),
            (
                ResolvedSetup {
                    value: SetupValue::Dxvk {
                        version: None,
                        nvapi: false,
                    },
                    source: Provenance::Default,
                },
                r#"{"value":{"kind":"dxvk","version":null,"nvapi":false},"source":"default"}"#,
            ),
            (
                ResolvedSetup {
                    value: SetupValue::Dalamud { enabled: true },
                    source: Provenance::Prefix,
                },
                r#"{"value":{"kind":"dalamud","enabled":true},"source":"prefix"}"#,
            ),
        ];

        for (setup, expected) in cases {
            let json = serde_json::to_string(&ResolvedSetupDto::from(&setup)).unwrap_or_default();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn support_preview_is_typed_in_core_order() {
        let parts = apogee_core::support_bundle_contents()
            .into_iter()
            .map(BundlePartDto::from)
            .collect::<Vec<_>>();
        let json = serde_json::to_string(&parts).unwrap_or_default();

        assert_eq!(
            json,
            r#"["systemReport","recentLogs","profiles","settings","shellFacts"]"#
        );
    }
}
