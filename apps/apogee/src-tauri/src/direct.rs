//! Direct, read-only queries whose answers do not belong on a command event stream.

use std::sync::Arc;

use apogee_core::{Core, Uuid};

use crate::dto::IpcErrorDto;
use crate::dto::read::{BundlePartDto, CatalogEntryDto, NextActionDto, ResolvedSetupDto};
use crate::dto::store::DefaultsDto;
use crate::{ShellState, run_blocking};

fn profile_id(profile: &str) -> Result<Uuid, IpcErrorDto> {
    Uuid::parse_str(profile).map_err(|_| IpcErrorDto::shell("shell.command.invalid"))
}

async fn blocking_core_result<T, F>(core: Arc<Core>, task: F) -> Result<T, IpcErrorDto>
where
    T: Send + 'static,
    F: FnOnce(&Core) -> Result<T, IpcErrorDto> + Send + 'static,
{
    run_blocking(move || task(&core)).await?
}

#[tauri::command]
pub(super) async fn next_action(
    state: tauri::State<'_, ShellState>,
    profile: String,
) -> Result<NextActionDto, IpcErrorDto> {
    let profile = profile_id(&profile)?;
    let (core, _permit) = state.ready_core_for_direct_read().await?;
    core.next_action(profile)
        .await
        .map(|action| NextActionDto::from(&action))
        .map_err(|error| IpcErrorDto::core(&error))
}

#[tauri::command]
pub(super) async fn defaults(
    state: tauri::State<'_, ShellState>,
) -> Result<DefaultsDto, IpcErrorDto> {
    let core = state.ready_core().await?;
    Ok(DefaultsDto::from(&core.defaults()))
}

#[tauri::command]
pub(super) async fn resolved_setup(
    state: tauri::State<'_, ShellState>,
    profile: String,
) -> Result<Vec<ResolvedSetupDto>, IpcErrorDto> {
    let profile = profile_id(&profile)?;
    let (core, _permit) = state.ready_core_for_direct_read().await?;
    core.resolved_setup(profile)
        .await
        .map(|setups| setups.iter().map(ResolvedSetupDto::from).collect())
        .map_err(|error| IpcErrorDto::core(&error))
}

#[tauri::command]
pub(super) async fn runner_catalog(
    state: tauri::State<'_, ShellState>,
) -> Result<Vec<CatalogEntryDto>, IpcErrorDto> {
    let (core, _permit) = state.ready_core_for_direct_read().await?;
    core.runner_catalog()
        .await
        .map(|entries| entries.iter().map(CatalogEntryDto::from).collect())
        .map_err(|error| IpcErrorDto::core(&error))
}

#[tauri::command]
pub(super) async fn dxvk_catalog(
    state: tauri::State<'_, ShellState>,
    profile: String,
) -> Result<Vec<CatalogEntryDto>, IpcErrorDto> {
    let profile = profile_id(&profile)?;
    let (core, _permit) = state.ready_core_for_direct_read().await?;
    core.dxvk_catalog(profile)
        .await
        .map(|entries| entries.iter().map(CatalogEntryDto::from).collect())
        .map_err(|error| IpcErrorDto::core(&error))
}

#[tauri::command]
pub(super) async fn system_report(
    state: tauri::State<'_, ShellState>,
    profile: Option<String>,
) -> Result<String, IpcErrorDto> {
    let profile = profile.as_deref().map(profile_id).transpose()?;
    let (core, _permit) = state.ready_core_for_direct_read().await?;
    blocking_core_result(core, move |core| {
        core.system_report(profile)
            .map_err(|error| IpcErrorDto::core(&error))
    })
    .await
}

#[tauri::command]
pub(super) async fn support_bundle_contents() -> Result<Vec<BundlePartDto>, IpcErrorDto> {
    Ok(apogee_core::support_bundle_contents()
        .into_iter()
        .map(BundlePartDto::from)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_profile_ids_stop_at_the_shell_boundary() {
        let error = profile_id("not-a-profile").expect_err("invalid UUID must be rejected");
        assert_eq!(
            serde_json::to_string(&error).unwrap_or_default(),
            r#"{"code":"shell.command.invalid","error":null}"#
        );
    }
}
