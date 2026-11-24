//! Path-free request and result shapes for direct store mutations.

use std::net::IpAddr;

use apogee_core::{
    AccountKind, Deviation, Gamescope, GpuSelect, Hud, LaunchSettings, ListenerSettings,
    ListenerSources, ProfileRemoval, Region, RunnerSelection, Secret, SecretBackend, SecretKind,
    SecretSweep, Settings, StableCode, SyncChoice, Uuid,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::secrets::SecretBytes;
use super::store::AccountDto;

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "UpdateAccountRequest.ts")]
pub(crate) struct UpdateAccountRequestDto {
    #[ts(type = "string")]
    account: Uuid,
    square_enix_id: String,
    kind: AccountKindInputDto,
    use_otp: bool,
}

impl UpdateAccountRequestDto {
    pub(crate) fn into_parts(self) -> (Uuid, String, AccountKind, bool) {
        (
            self.account,
            self.square_enix_id,
            self.kind.into_core(),
            self.use_otp,
        )
    }
}

#[derive(Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[ts(export, export_to = "AccountKindInput.ts")]
enum AccountKindInputDto {
    Standard,
    Steam { app_id: u32 },
    FreeTrial,
}

impl AccountKindInputDto {
    fn into_core(self) -> AccountKind {
        match self {
            Self::Standard => AccountKind::Standard,
            Self::Steam { app_id } => AccountKind::Steam { app_id },
            Self::FreeTrial => AccountKind::FreeTrial,
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "UpdateProfileRequest.ts")]
pub(crate) struct UpdateProfileRequestDto {
    #[ts(type = "string")]
    profile: Uuid,
    name: String,
    runner: RunnerSelectionInputDto,
    launch: LaunchSettingsInputDto,
}

impl UpdateProfileRequestDto {
    pub(crate) fn into_parts(self) -> (Uuid, String, RunnerSelection, LaunchSettings) {
        (
            self.profile,
            self.name,
            self.runner.into_core(),
            self.launch.into_core(),
        )
    }
}

#[derive(Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[ts(export, export_to = "RunnerSelectionInput.ts")]
enum RunnerSelectionInputDto {
    SystemWine,
    Managed { name: String, version: String },
}

impl RunnerSelectionInputDto {
    fn into_core(self) -> RunnerSelection {
        match self {
            Self::SystemWine => RunnerSelection::SystemWine,
            Self::Managed { name, version } => RunnerSelection::Managed { name, version },
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "LaunchSettingsInput.ts")]
struct LaunchSettingsInputDto {
    region: RegionInputDto,
    extra_args: Vec<String>,
    extra_env: Vec<EnvironmentEntryInputDto>,
    wrappers: Vec<String>,
    sync: SyncChoiceInputDto,
    hud: HudInputDto,
    gpu: GpuSelectInputDto,
    nvapi: bool,
    gamescope: Option<GamescopeInputDto>,
    gamemode: bool,
    dalamud: bool,
}

impl LaunchSettingsInputDto {
    fn into_core(self) -> LaunchSettings {
        LaunchSettings {
            region: self.region.into_core(),
            extra_args: self.extra_args,
            extra_env: self
                .extra_env
                .into_iter()
                .map(EnvironmentEntryInputDto::into_pair)
                .collect(),
            wrappers: self.wrappers,
            sync: self.sync.into_core(),
            hud: self.hud.into_core(),
            gpu: self.gpu.into_core(),
            nvapi: self.nvapi,
            gamescope: self.gamescope.map(GamescopeInputDto::into_core),
            gamemode: self.gamemode,
            dalamud: self.dalamud,
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "EnvironmentEntryInput.ts")]
struct EnvironmentEntryInputDto {
    name: String,
    value: String,
}

impl EnvironmentEntryInputDto {
    fn into_pair(self) -> (String, String) {
        (self.name, self.value)
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "GamescopeInput.ts")]
struct GamescopeInputDto {
    width: Option<u32>,
    height: Option<u32>,
    refresh: Option<u32>,
    fullscreen: bool,
    hdr: bool,
    extra: Vec<String>,
}

impl GamescopeInputDto {
    fn into_core(self) -> Gamescope {
        Gamescope {
            width: self.width,
            height: self.height,
            refresh: self.refresh,
            fullscreen: self.fullscreen,
            hdr: self.hdr,
            extra: self.extra,
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "RegionInput.ts")]
enum RegionInputDto {
    Global,
    Korea,
    China,
}

impl RegionInputDto {
    const fn into_core(self) -> Region {
        match self {
            Self::Global => Region::Global,
            Self::Korea => Region::Korea,
            Self::China => Region::China,
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "SyncChoiceInput.ts")]
enum SyncChoiceInputDto {
    Auto,
    Ntsync,
    Fsync,
    Esync,
    None,
}

impl SyncChoiceInputDto {
    const fn into_core(self) -> SyncChoice {
        match self {
            Self::Auto => SyncChoice::Auto,
            Self::Ntsync => SyncChoice::Ntsync,
            Self::Fsync => SyncChoice::Fsync,
            Self::Esync => SyncChoice::Esync,
            Self::None => SyncChoice::None,
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
#[ts(export, export_to = "HudInput.ts")]
enum HudInputDto {
    None,
    Dxvk(String),
    Mango,
}

impl HudInputDto {
    fn into_core(self) -> Hud {
        match self {
            Self::None => Hud::None,
            Self::Dxvk(value) => Hud::Dxvk(value),
            Self::Mango => Hud::Mango,
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
#[ts(export, export_to = "GpuSelectInput.ts")]
enum GpuSelectInputDto {
    Default,
    NvidiaPrime,
    MesaPrime,
    VulkanDevice(String),
}

impl GpuSelectInputDto {
    fn into_core(self) -> GpuSelect {
        match self {
            Self::Default => GpuSelect::Default,
            Self::NvidiaPrime => GpuSelect::NvidiaPrime,
            Self::MesaPrime => GpuSelect::MesaPrime,
            Self::VulkanDevice(device) => GpuSelect::VulkanDevice(device),
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "UpdateSettingsRequest.ts")]
pub(crate) struct UpdateSettingsRequestDto {
    language: String,
    close_after_launch: bool,
    secret_backend: SecretBackendInputDto,
    keep_patches: bool,
    backups_kept: u32,
    backup_before_patch: bool,
    frontier_poll_seconds: u64,
    otp_listener: ListenerSettingsInputDto,
}

impl UpdateSettingsRequestDto {
    pub(crate) fn into_core(self) -> Settings {
        Settings {
            language: self.language,
            close_after_launch: self.close_after_launch,
            secret_backend: self.secret_backend.into_core(),
            keep_patches: self.keep_patches,
            backups_kept: self.backups_kept,
            backup_before_patch: self.backup_before_patch,
            frontier_poll_seconds: self.frontier_poll_seconds,
            otp_listener: self.otp_listener.into_core(),
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "SecretBackendInput.ts")]
enum SecretBackendInputDto {
    Platform,
    EncryptedFile,
    Nothing,
}

impl SecretBackendInputDto {
    const fn into_core(self) -> SecretBackend {
        match self {
            Self::Platform => SecretBackend::Platform,
            Self::EncryptedFile => SecretBackend::EncryptedFile,
            Self::Nothing => SecretBackend::Nothing,
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "ListenerSettingsInput.ts")]
struct ListenerSettingsInputDto {
    #[ts(type = "string")]
    bind: IpAddr,
    port: u16,
    sources: ListenerSourcesInputDto,
    wait_seconds: u64,
}

impl ListenerSettingsInputDto {
    fn into_core(self) -> ListenerSettings {
        ListenerSettings {
            bind: self.bind,
            port: self.port,
            sources: self.sources.into_core(),
            wait_seconds: self.wait_seconds,
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[ts(export, export_to = "ListenerSourcesInput.ts")]
enum ListenerSourcesInputDto {
    Any,
    Only {
        #[ts(type = "string[]")]
        addresses: Vec<IpAddr>,
    },
}

impl ListenerSourcesInputDto {
    fn into_core(self) -> ListenerSources {
        match self {
            Self::Any => ListenerSources::Any,
            Self::Only { addresses } => ListenerSources::Only { addresses },
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "DeleteSecretRequest.ts")]
pub(crate) struct DeleteSecretRequestDto {
    #[ts(type = "string")]
    account: Uuid,
    kind: SecretKindDto,
    confirmed: bool,
}

impl DeleteSecretRequestDto {
    pub(crate) fn into_parts(self) -> (Uuid, SecretKind, bool) {
        (self.account, self.kind.into_core(), self.confirmed)
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "SecretKind.ts")]
enum SecretKindDto {
    Password,
    TotpSecret,
}

/// A password crosses only as bytes and has no outbound representation.
#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "StorePasswordRequest.ts")]
pub(crate) struct StorePasswordRequestDto {
    #[ts(type = "string")]
    account: Uuid,
    #[ts(type = "number[]")]
    password: SecretBytes,
}

impl StorePasswordRequestDto {
    pub(crate) fn into_parts(self) -> (Uuid, Secret) {
        (self.account, self.password.into_secret())
    }
}

/// A pasted generator URI or base32 value crosses once as zeroizing bytes.
#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "ImportTotpSecretRequest.ts")]
pub(crate) struct ImportTotpSecretRequestDto {
    #[ts(type = "string")]
    account: Uuid,
    #[ts(type = "number[]")]
    secret: SecretBytes,
}

impl ImportTotpSecretRequestDto {
    pub(crate) fn into_parts(self) -> (Uuid, Secret) {
        (self.account, self.secret.into_secret())
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "UsePushedCodesRequest.ts")]
pub(crate) struct UsePushedCodesRequestDto {
    #[ts(type = "string")]
    account: Uuid,
    confirmation: String,
}

impl UsePushedCodesRequestDto {
    pub(crate) fn into_parts(self) -> (Uuid, String) {
        (self.account, self.confirmation)
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "DisablePushedCodesRequest.ts")]
pub(crate) struct DisablePushedCodesRequestDto {
    #[ts(type = "string")]
    account: Uuid,
}

impl DisablePushedCodesRequestDto {
    pub(crate) const fn account(self) -> Uuid {
        self.account
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(export, export_to = "TotpDeviation.ts")]
pub(crate) enum TotpDeviationDto {
    Algorithm {
        offered: &'static str,
        accepted: &'static str,
    },
    Digits {
        offered: u8,
        accepted: u8,
    },
    Period {
        offered: u32,
        accepted: u32,
    },
    Unknown {
        code: &'static str,
    },
}

impl From<&Deviation> for TotpDeviationDto {
    fn from(deviation: &Deviation) -> Self {
        match deviation {
            Deviation::Algorithm { offered, accepted } => Self::Algorithm {
                offered: offered.label(),
                accepted: accepted.label(),
            },
            Deviation::Digits { offered, accepted } => Self::Digits {
                offered: *offered,
                accepted: *accepted,
            },
            Deviation::Period { offered, accepted } => Self::Period {
                offered: *offered,
                accepted: *accepted,
            },
            _ => Self::Unknown {
                code: deviation.code(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "TotpImportResult.ts")]
pub(crate) struct TotpImportResultDto {
    account: AccountDto,
    deviations: Vec<TotpDeviationDto>,
}

impl TotpImportResultDto {
    pub(crate) fn new(account: AccountDto, deviations: Vec<Deviation>) -> Self {
        Self {
            account,
            deviations: deviations.iter().map(TotpDeviationDto::from).collect(),
        }
    }
}

impl SecretKindDto {
    const fn into_core(self) -> SecretKind {
        match self {
            Self::Password => SecretKind::Password,
            Self::TotpSecret => SecretKind::TotpSecret,
        }
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "ForgetSecretsRequest.ts")]
pub(crate) struct ForgetSecretsRequestDto {
    #[ts(type = "string")]
    account: Uuid,
    confirmed: bool,
}

impl ForgetSecretsRequestDto {
    pub(crate) const fn into_parts(self) -> (Uuid, bool) {
        (self.account, self.confirmed)
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "SetNeverStoreRequest.ts")]
pub(crate) struct SetNeverStoreRequestDto {
    #[ts(type = "string")]
    account: Uuid,
    on: bool,
}

impl SetNeverStoreRequestDto {
    pub(crate) const fn into_parts(self) -> (Uuid, bool) {
        (self.account, self.on)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "NeverStoreResult.ts")]
pub(crate) struct NeverStoreResultDto {
    account: AccountDto,
    secret_sweep: Option<SecretSweepDto>,
}

impl NeverStoreResultDto {
    pub(crate) fn new(account: AccountDto, secret_sweep: Option<SecretSweep>) -> Self {
        Self {
            account,
            secret_sweep: secret_sweep.map(SecretSweepDto::from),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "ForgetSecretsResult.ts")]
pub(crate) struct ForgetSecretsResultDto {
    account: AccountDto,
    secret_sweep: SecretSweepDto,
}

impl ForgetSecretsResultDto {
    pub(crate) fn new(account: AccountDto, secret_sweep: SecretSweep) -> Self {
        Self {
            account,
            secret_sweep: SecretSweepDto::from(secret_sweep),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "ProfileRemovalPlan.ts")]
pub(crate) struct ProfileRemovalPlanDto {
    request_id: String,
    profile: String,
    account_removed: Option<String>,
}

impl ProfileRemovalPlanDto {
    pub(crate) fn new(request_id: Uuid, profile: Uuid, account_removed: Option<Uuid>) -> Self {
        Self {
            request_id: request_id.to_string(),
            profile: profile.to_string(),
            account_removed: account_removed.map(|account| account.to_string()),
        }
    }

    #[cfg(test)]
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }
}

#[derive(Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(export, export_to = "RemoveProfileRequest.ts")]
pub(crate) struct RemoveProfileRequestDto {
    request_id: String,
    confirmed: bool,
}

impl RemoveProfileRequestDto {
    pub(crate) fn into_parts(self) -> (String, bool) {
        (self.request_id, self.confirmed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "ProfileRemoval.ts")]
pub(crate) struct ProfileRemovalDto {
    profile_removed: String,
    account_removed: Option<String>,
    secret_sweep: Option<SecretSweepDto>,
}

impl ProfileRemovalDto {
    pub(crate) fn new(profile: Uuid, removal: ProfileRemoval) -> Self {
        Self {
            profile_removed: profile.to_string(),
            account_removed: removal.account_removed.map(|account| account.to_string()),
            secret_sweep: removal.secret_sweep.map(SecretSweepDto::from),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SecretSweep.ts")]
pub(crate) enum SecretSweepDto {
    Swept,
    Unanswered,
    LeftBehind,
    Unknown,
}

impl From<SecretSweep> for SecretSweepDto {
    fn from(sweep: SecretSweep) -> Self {
        match sweep {
            SecretSweep::Swept => Self::Swept,
            SecretSweep::Unanswered => Self::Unanswered,
            SecretSweep::LeftBehind => Self::LeftBehind,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_json() -> serde_json::Value {
        serde_json::json!({
            "region": "global",
            "extraArgs": [],
            "extraEnv": [],
            "wrappers": [],
            "sync": "auto",
            "hud": { "kind": "none" },
            "gpu": { "kind": "default" },
            "nvapi": false,
            "gamescope": null,
            "gamemode": false,
            "dalamud": false,
        })
    }

    #[test]
    fn account_updates_cannot_deserialize_preserved_fields() {
        let request = serde_json::json!({
            "account": Uuid::nil(),
            "squareEnixId": "updated",
            "kind": { "kind": "standard" },
            "useOtp": true,
            "neverStore": false,
        });

        assert!(serde_json::from_value::<UpdateAccountRequestDto>(request).is_err());
    }

    #[test]
    fn profile_updates_cannot_deserialize_path_or_ownership_fields() {
        let request = serde_json::json!({
            "profile": Uuid::nil(),
            "name": "updated",
            "runner": { "kind": "systemWine" },
            "launch": launch_json(),
            "gamePath": "/planted/path",
        });

        assert!(serde_json::from_value::<UpdateProfileRequestDto>(request).is_err());
    }

    #[test]
    fn nested_update_fields_reject_unknown_data() {
        let mut launch = launch_json();
        launch["gamePath"] = serde_json::json!("/planted/path");
        let request = serde_json::json!({
            "profile": Uuid::nil(),
            "name": "updated",
            "runner": { "kind": "systemWine" },
            "launch": launch,
        });

        assert!(serde_json::from_value::<UpdateProfileRequestDto>(request).is_err());
    }

    #[test]
    fn tagged_launch_choices_reject_smuggled_fields() {
        for field in ["hud", "gpu"] {
            let mut launch = launch_json();
            launch[field]["path"] = serde_json::json!("/planted/path");
            let request = serde_json::json!({
                "profile": Uuid::nil(),
                "name": "updated",
                "runner": { "kind": "systemWine" },
                "launch": launch,
            });

            assert!(serde_json::from_value::<UpdateProfileRequestDto>(request).is_err());
        }
    }

    #[test]
    fn listener_consent_is_an_exact_typed_word() {
        let request = serde_json::json!({
            "account": Uuid::nil(),
            "confirmation": "listen",
            "confirmed": true,
        });

        assert!(serde_json::from_value::<UsePushedCodesRequestDto>(request).is_err());
    }

    #[test]
    fn settings_validate_listener_addresses_during_deserialization() {
        let request = serde_json::json!({
            "language": "en",
            "closeAfterLaunch": false,
            "secretBackend": "platform",
            "keepPatches": true,
            "backupsKept": 5,
            "backupBeforePatch": true,
            "frontierPollSeconds": 30,
            "otpListener": {
                "bind": "not-an-address",
                "port": 4646,
                "sources": { "kind": "any" },
                "waitSeconds": 90,
            },
        });

        assert!(serde_json::from_value::<UpdateSettingsRequestDto>(request).is_err());
    }
}
