//! Persisted launcher records in a shell-owned read format.

use std::net::IpAddr;

use apogee_core::{
    Account, AccountKind, Defaults, ExternalAddon, ExternalAddonProblem, Gamescope, GpuSelect, Hud,
    LaunchSettings, ListenerSettings, ListenerSources, OtpDelivery, PrefixSelection, Profile,
    Region, RunIn, RunnerSelection, SecretBackend, Settings, SyncChoice, Trigger,
};
use serde::Serialize;
use ts_rs::TS;

use super::path::PathDto;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileDto {
    id: String,
    name: String,
    account: String,
    game_path: PathDto,
    runner: RunnerSelectionDto,
    prefix: PrefixSelectionDto,
    external: Vec<ExternalAddonDto>,
    launch: LaunchSettingsDto,
}

impl From<&Profile> for ProfileDto {
    fn from(profile: &Profile) -> Self {
        Self {
            id: profile.id.to_string(),
            name: profile.name.clone(),
            account: profile.account.to_string(),
            game_path: PathDto::from(profile.game_path.as_path()),
            runner: RunnerSelectionDto::from(&profile.runner),
            prefix: PrefixSelectionDto::from(&profile.prefix),
            external: profile
                .external
                .iter()
                .map(ExternalAddonDto::from)
                .collect(),
            launch: LaunchSettingsDto::from(&profile.launch),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
struct PrefixSelectionDto {
    name: String,
}

impl From<&PrefixSelection> for PrefixSelectionDto {
    fn from(prefix: &PrefixSelection) -> Self {
        Self {
            name: prefix.name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum RunnerSelectionDto {
    SystemWine,
    Managed { name: String, version: String },
    Unknown,
}

impl From<&RunnerSelection> for RunnerSelectionDto {
    fn from(runner: &RunnerSelection) -> Self {
        match runner {
            RunnerSelection::SystemWine => Self::SystemWine,
            RunnerSelection::Managed { name, version } => Self::Managed {
                name: name.clone(),
                version: version.clone(),
            },
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
struct ExternalAddonDto {
    program: PathDto,
    args: Vec<String>,
    run_in: RunInDto,
    trigger: TriggerDto,
    enabled: bool,
    problem: Option<ExternalAddonProblemDto>,
}

impl From<&ExternalAddon> for ExternalAddonDto {
    fn from(addon: &ExternalAddon) -> Self {
        Self {
            program: PathDto::from(addon.program()),
            args: addon.args().to_vec(),
            run_in: RunInDto::from(addon.run_in()),
            trigger: TriggerDto::from(addon.trigger()),
            enabled: addon.enabled(),
            problem: addon
                .configuration_problem()
                .map(ExternalAddonProblemDto::from),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum ExternalAddonProblemDto {
    InvalidProgram,
    UnsupportedFields,
    Unknown,
}

impl From<ExternalAddonProblem> for ExternalAddonProblemDto {
    fn from(problem: ExternalAddonProblem) -> Self {
        match problem {
            ExternalAddonProblem::InvalidProgram => Self::InvalidProgram,
            ExternalAddonProblem::UnsupportedFields => Self::UnsupportedFields,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum RunInDto {
    Host,
    Prefix,
    Unknown,
}

impl From<RunIn> for RunInDto {
    fn from(run_in: RunIn) -> Self {
        match run_in {
            RunIn::Host => Self::Host,
            RunIn::Prefix => Self::Prefix,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum TriggerDto {
    WithGame { keep_after_close: bool },
    OnClose,
    Unknown,
}

impl From<Trigger> for TriggerDto {
    fn from(trigger: Trigger) -> Self {
        match trigger {
            Trigger::WithGame { keep_after_close } => Self::WithGame { keep_after_close },
            Trigger::OnClose => Self::OnClose,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LaunchSettingsDto {
    region: RegionDto,
    extra_args: Vec<String>,
    extra_env: Vec<EnvironmentEntryDto>,
    wrappers: Vec<String>,
    sync: SyncChoiceDto,
    hud: HudDto,
    gpu: GpuSelectDto,
    nvapi: bool,
    gamescope: Option<GamescopeDto>,
    gamemode: bool,
    dalamud: bool,
}

impl From<&LaunchSettings> for LaunchSettingsDto {
    fn from(launch: &LaunchSettings) -> Self {
        Self {
            region: RegionDto::from(launch.region),
            extra_args: launch.extra_args.clone(),
            extra_env: launch
                .extra_env
                .iter()
                .map(|(name, value)| EnvironmentEntryDto {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect(),
            wrappers: launch.wrappers.clone(),
            sync: SyncChoiceDto::from(launch.sync),
            hud: HudDto::from(&launch.hud),
            gpu: GpuSelectDto::from(&launch.gpu),
            nvapi: launch.nvapi,
            gamescope: launch.gamescope.as_ref().map(GamescopeDto::from),
            gamemode: launch.gamemode,
            dalamud: launch.dalamud,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
struct EnvironmentEntryDto {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum RegionDto {
    Global,
    Korea,
    China,
    Unknown,
}

impl From<Region> for RegionDto {
    fn from(region: Region) -> Self {
        match region {
            Region::Global => Self::Global,
            Region::Korea => Self::Korea,
            Region::China => Self::China,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum SyncChoiceDto {
    Auto,
    Ntsync,
    Fsync,
    Esync,
    None,
}

impl From<SyncChoice> for SyncChoiceDto {
    fn from(sync: SyncChoice) -> Self {
        match sync {
            SyncChoice::Auto => Self::Auto,
            SyncChoice::Ntsync => Self::Ntsync,
            SyncChoice::Fsync => Self::Fsync,
            SyncChoice::Esync => Self::Esync,
            SyncChoice::None => Self::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
enum HudDto {
    None,
    Dxvk(String),
    Mango,
}

impl From<&Hud> for HudDto {
    fn from(hud: &Hud) -> Self {
        match hud {
            Hud::None => Self::None,
            Hud::Dxvk(value) => Self::Dxvk(value.clone()),
            Hud::Mango => Self::Mango,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub(crate) enum GpuSelectDto {
    Default,
    NvidiaPrime,
    MesaPrime,
    VulkanDevice(String),
}

impl From<&GpuSelect> for GpuSelectDto {
    fn from(gpu: &GpuSelect) -> Self {
        match gpu {
            GpuSelect::Default => Self::Default,
            GpuSelect::NvidiaPrime => Self::NvidiaPrime,
            GpuSelect::MesaPrime => Self::MesaPrime,
            GpuSelect::VulkanDevice(device) => Self::VulkanDevice(device.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
struct GamescopeDto {
    width: Option<u32>,
    height: Option<u32>,
    refresh: Option<u32>,
    fullscreen: bool,
    hdr: bool,
    extra: Vec<String>,
}

impl From<&Gamescope> for GamescopeDto {
    fn from(gamescope: &Gamescope) -> Self {
        Self {
            width: gamescope.width,
            height: gamescope.height,
            refresh: gamescope.refresh,
            fullscreen: gamescope.fullscreen,
            hdr: gamescope.hdr,
            extra: gamescope.extra.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountDto {
    id: String,
    square_enix_id: String,
    kind: AccountKindDto,
    use_otp: bool,
    never_store: bool,
    otp_delivery: OtpDeliveryDto,
}

impl From<&Account> for AccountDto {
    fn from(account: &Account) -> Self {
        Self {
            id: account.id.to_string(),
            square_enix_id: account.sqex_id.clone(),
            kind: AccountKindDto::from(&account.kind),
            use_otp: account.use_otp,
            never_store: account.never_store,
            otp_delivery: OtpDeliveryDto::from(account.otp_delivery),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum AccountKindDto {
    Standard,
    Steam { app_id: u32 },
    FreeTrial,
    Unknown,
}

impl From<&AccountKind> for AccountKindDto {
    fn from(kind: &AccountKind) -> Self {
        match kind {
            AccountKind::Standard => Self::Standard,
            AccountKind::Steam { app_id } => Self::Steam { app_id: *app_id },
            AccountKind::FreeTrial => Self::FreeTrial,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum OtpDeliveryDto {
    Ask,
    Generate,
    Listen,
    Unknown,
}

impl From<OtpDelivery> for OtpDeliveryDto {
    fn from(delivery: OtpDelivery) -> Self {
        match delivery {
            OtpDelivery::Ask => Self::Ask,
            OtpDelivery::Generate => Self::Generate,
            OtpDelivery::Listen => Self::Listen,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SettingsDto {
    language: String,
    close_after_launch: bool,
    secret_backend: SecretBackendDto,
    keep_patches: bool,
    backups_kept: u32,
    backup_before_patch: bool,
    frontier_poll_seconds: u64,
    otp_listener: ListenerSettingsDto,
}

impl From<&Settings> for SettingsDto {
    fn from(settings: &Settings) -> Self {
        Self {
            language: settings.language.clone(),
            close_after_launch: settings.close_after_launch,
            secret_backend: SecretBackendDto::from(settings.secret_backend),
            keep_patches: settings.keep_patches,
            backups_kept: settings.backups_kept,
            backup_before_patch: settings.backup_before_patch,
            frontier_poll_seconds: settings.frontier_poll_seconds,
            otp_listener: ListenerSettingsDto::from(&settings.otp_listener),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
enum SecretBackendDto {
    Platform,
    EncryptedFile,
    Nothing,
    Unknown,
}

impl From<SecretBackend> for SecretBackendDto {
    fn from(backend: SecretBackend) -> Self {
        match backend {
            SecretBackend::Platform => Self::Platform,
            SecretBackend::EncryptedFile => Self::EncryptedFile,
            SecretBackend::Nothing => Self::Nothing,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
struct ListenerSettingsDto {
    bind: String,
    port: u16,
    sources: ListenerSourcesDto,
    wait_seconds: u64,
}

impl From<&ListenerSettings> for ListenerSettingsDto {
    fn from(listener: &ListenerSettings) -> Self {
        Self {
            bind: listener.bind.to_string(),
            port: listener.port,
            sources: ListenerSourcesDto::from(&listener.sources),
            wait_seconds: listener.wait_seconds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum ListenerSourcesDto {
    Any,
    Only { addresses: Vec<String> },
    Unknown,
}

impl From<&ListenerSources> for ListenerSourcesDto {
    fn from(sources: &ListenerSources) -> Self {
        match sources {
            ListenerSources::Any => Self::Any,
            ListenerSources::Only { addresses } => Self::Only {
                addresses: addresses.iter().map(IpAddr::to_string).collect(),
            },
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DefaultsDto {
    settings: SettingsDto,
    launch: LaunchSettingsDto,
}

impl From<&Defaults> for DefaultsDto {
    fn from(defaults: &Defaults) -> Self {
        Self {
            settings: SettingsDto::from(&defaults.settings),
            launch: LaunchSettingsDto::from(&defaults.launch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apogee_core::Uuid;

    #[test]
    fn account_projection_contains_no_secret_presence_claim() {
        let account = Account::new("person@example.invalid", AccountKind::Standard);
        let json = serde_json::to_string(&AccountDto::from(&account)).unwrap_or_default();

        assert!(json.contains(&account.id.to_string()));
        assert!(json.contains("person@example.invalid"));
        assert!(!json.contains("password"));
        assert!(!json.contains("stored"));
    }

    #[test]
    fn profile_projection_keeps_user_overrides_and_exact_path() {
        let account = Uuid::nil();
        let mut profile = Profile::new("Main", account, "install/game".into());
        profile.launch.extra_args = vec!["--example".to_owned()];
        profile.launch.extra_env = vec![("KEY".to_owned(), "value".to_owned())];
        profile.launch.wrappers = vec!["wrapper".to_owned()];

        let json = serde_json::to_string(&ProfileDto::from(&profile)).unwrap_or_default();
        assert!(json.contains("--example"));
        assert!(json.contains(r#""name":"KEY","value":"value""#));
        assert!(json.contains(r#""display":"install/game""#));
    }

    #[test]
    fn unsupported_external_fields_are_visible_without_crossing_the_field() {
        let value = serde_json::json!({
            "program": std::env::temp_dir().join("tool"),
            "run_in": "host",
            "trigger": "on_close",
            "token_shaped_future_field": "planted-secret"
        });
        let addon = serde_json::from_value::<ExternalAddon>(value);
        assert!(addon.is_ok());
        let json = addon
            .as_ref()
            .ok()
            .and_then(|addon| serde_json::to_string(&ExternalAddonDto::from(addon)).ok())
            .unwrap_or_default();

        assert!(json.contains(r#""problem":"unsupportedFields""#));
        assert!(!json.contains("token_shaped_future_field"));
        assert!(!json.contains("planted-secret"));
    }
}
