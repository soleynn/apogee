//! The local, deterministic snapshot returned before the frontend renders store state.

use apogee_core::Core;
use serde::Serialize;
use ts_rs::TS;

use super::IpcErrorDto;
use super::store::{AccountDto, DefaultsDto, ProfileDto, SettingsDto};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "Startup.ts")]
pub(crate) struct StartupDto {
    version: &'static str,
    profiles: Vec<ProfileDto>,
    accounts: Vec<AccountDto>,
    settings: SettingsDto,
    defaults: DefaultsDto,
}

impl StartupDto {
    pub(crate) fn read(core: &Core) -> Result<Self, IpcErrorDto> {
        let profiles = core.profiles().map_err(|error| IpcErrorDto::core(&error))?;
        let accounts = core.accounts().map_err(|error| IpcErrorDto::core(&error))?;
        let settings = core.settings().map_err(|error| IpcErrorDto::core(&error))?;
        let defaults = core.defaults();
        Ok(Self {
            version: env!("CARGO_PKG_VERSION"),
            profiles: profiles.iter().map(ProfileDto::from).collect(),
            accounts: accounts.iter().map(AccountDto::from).collect(),
            settings: SettingsDto::from(&settings),
            defaults: DefaultsDto::from(&defaults),
        })
    }
}
